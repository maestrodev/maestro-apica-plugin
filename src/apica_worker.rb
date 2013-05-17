# Copyright (c) 2013 MaestroDev.  All rights reserved.
require 'net/http'
require 'net/https'
require 'uri'
require 'timeout'
require 'maestro_plugin'

module MaestroDev
  class PermissionsError < StandardError
  end

  class ForbiddenError < PermissionsError
  end

  class UnauthorizedError < PermissionsError
  end

  class ApicaAPIError < StandardError
  end

  class TestAbortError < StandardError
  end

  class ConfigError < StandardError
  end

  class ApicaWorker < Maestro::MaestroWorker
    DEFAULT_COMPARISON_HISTORY = 5
    DEFAULT_TIMEOUT = 900
    MAX_COMPARISON_HISTORY = 6
    SNOOZE = 5

    WELL_KNOWN_DURATION = 'duration'
    WELL_KNOWN_SKIP = 'skipped'
    WELL_KNOWN_FAIL = 'failures'
    WELL_KNOWN_PASS = 'passed'
    WELL_KNOWN_TOTAL = 'tests'

    # 'Int'     - Non-quoted
    # 'Decimal' - Non-quoted
    # 'String'  - Quoted
    APICA_KEY_SUCCESS = 'Success'
    APICA_KEY_MESSAGE = 'Message'
    APICA_KEY_JOBID   = 'Job id'
    APICA_KEY_STATUS  = 'Status message'
    APICA_KEY_TEST_RESULTS_URL = 'Link to testresults'
    APICA_KEY_METADATA = 'Test metadata'
    APICA_KEY_METADATA_DURATION = 'Test duration (sec)'                                # Int
    APICA_KEY_PERF     = 'Performance summary'
    APICA_KEY_PERF_TOTAL_PASS_LOOPS = 'Total passed loops'                             # Int
    APICA_KEY_PERF_TOTAL_FAIL_LOOPS = 'Total failed loops'                             # Int
    APICA_KEY_PERF_SESSION_FAILURE_RATE = 'Session failure rate (soft errors, %)'      # Decimal
    APICA_KEY_PERF_URL_ERROR_RATE = 'Url error rate (hard errors, %)'                  # Decimal
    APICA_KEY_PERF_AVG_THROUGHPUT = 'Average network throughput'                       # String
    APICA_KEY_PERF_AVG_THROUGHPUT_UNIT = 'Avg. network throughput unit of measurement' # String
    APICA_KEY_PERF_AVG_SESSION_TIME_PER_LOOP = 'Average session time per loop (s)'     # Decimal
    APICA_KEY_PERF_AVG_RESPONSE_TIME_PER_LOOP = 'Average response time per loop (s)'   # Decimal
    APICA_KEY_PERF_WEB_TRANSACTION_RATE = 'Web transaction rate (Hits/s)'              # Decimal
    APICA_KEY_PERF_AVG_RESPONSE_TIME_PER_PAGE = 'Average response time per page (s)'   # Decimal
    APICA_KEY_PERF_TOTAL_HTTP_CALLS = 'Total http(s) calls'                            # Int
    APICA_KEY_PERF_KEEP_ALIVE_EFFICIENCY = 'Http keep-alive efficiency'                # Decimal
    APICA_KEY_PERF_AVG_NETWORK_CONNECT_TIME = 'Avg network connect time (ms)'          # Int
    APICA_KEY_PERF_TOTAL_TRANSMITTED_BYTES = 'Total transmitted bytes'                 # Int
    
    def validate_parameters
      # Server & Auth
      @server_url = get_field('server_url', '')
      @user = get_field('user', '')
      @password = get_field('password')
      @timeout = get_field('timeout', DEFAULT_TIMEOUT)

      # Work
      @test_list = get_field('command_string', '')
      @comparison_history = get_field('comparison_history', DEFAULT_COMPARISON_HISTORY)
      @report_mailing_list = get_field('report_mailing_list', [])

      errors = []
      errors << 'Invalid server' if @server_url.empty?
      errors << "Server URL must start with 'http://' or 'https://'" if !@server_url.start_with?('http://', 'https://')
      errors << 'Invalid user' if @user.empty?
      errors << 'No tests specified' if @test_list.empty?
      errors << "Comparison History must be between 0 and #{MAX_COMPARISON_HISTORY}" if @comparison_history < 0 || @comparison_history > MAX_COMPARISON_HISTORY

      if !errors.empty?
        raise ConfigError, "Configuration errors: #{errors.join(', ')}"
      end
    end

    def loadtest
      write_output("\nAPICA LOADTEST task starting", :buffer => true)

      begin
        # Raises error if invalid params passed
        validate_parameters

        # Fix test-list so its an array
        @test_list = @test_list.split("\n")
        @test_list.delete_if {|v| v.nil? || v.empty?}

        write_output("\n\nConfiguration:", :buffer => true)
        write_output("\n  Server URL: #{@server_url}", :buffer => true)
        write_output("\n  User: #{@user}", :buffer => true)
        write_output("\n  Password: ********", :buffer => true)
        write_output("\n  Timeout: #{@timeout} seconds", :buffer => true)
        write_output("\n  Compare against: last #{@comparison_history} runs", :buffer => true)
        write_output("\n  Email test reports to: #{@report_mailing_list.join(', ')}", :buffer => true)
        write_output("\n  Total tests to run: #{@test_list.size}")

        test_meta = []
        url_meta = {}

        # Execute tests in sequence - per python example
        @test_list.each do |item|
          # Item consists of "ConfigurationName<comma>RunnableFileName"
          # The second param appears to be optional
          cols = item.split(',')

          if !cols.empty?
            # If we didn't get an executable name, throw in a blank
            if cols.size < 2
              cols << ''
            end

            data = {"ConfigurationName" => cols[0],
                    "RunnableFileName" => cols[1],
                    "ReportingOptions" => {
                      "ComparisonHistory" => @comparison_history,
                      "ReportMailingList" => @report_mailing_list
                    }}

            write_output "\n\nInitiating load-test '#{cols[0]}:#{cols[1]}'"

            response = nil

            begin
              response = do_put('', JSON.generate(data))
            rescue Exception => e
              raise TestAbortError, "Error invoking test '#{cols[0]}:#{cols[1]}' with payload\n#{JSON.pretty_generate(data)}\nError: #{e.class} #{e}"
            end

            apica_data = process_apica_response('Start load-test', response.body)

            # With the Test Job Id we can poll to see the progress of the job
            job_id = apica_data[APICA_KEY_JOBID]

            write_output "\nJob #{job_id}: Initiated"
            test_complete = true
            last_status = ''

            Timeout::timeout(@timeout) {
              begin
                sleep SNOOZE
                response = do_get("/#{job_id}")
                apica_data = process_apica_response('Get load-test status', response.body)
                status = apica_data[APICA_KEY_STATUS]

                if status != last_status
                  write_output("\nJob #{job_id}: #{status}")
                else
                  write_output('.')
                end

                last_status = status
                test_complete = apica_data["Job completed successfully"]
              end while !test_complete
            }

            report_url = apica_data[APICA_KEY_TEST_RESULTS_URL]

            if !report_url.nil? && !report_url.empty?
              url_meta["Job ##{job_id}"] = report_url
              add_link("Apica Job ##{job_id}", report_url)
              write_output("\nJob #{job_id}: Report viewable at #{report_url}")
            end

            meta = apica_data[APICA_KEY_METADATA] || {}
            perf = apica_data[APICA_KEY_PERF] || {}

            # Add some meta-meta
            # Like total test #, duration, etc
            # using what will hopefully be "well known keys" so UI doesn't have to be too smart
            perf[WELL_KNOWN_DURATION] = meta[APICA_KEY_METADATA_DURATION] || 0
            perf[WELL_KNOWN_PASS] = perf[APICA_KEY_PERF_TOTAL_PASS_LOOPS] || 0
            perf[WELL_KNOWN_FAIL] = perf[APICA_KEY_PERF_TOTAL_FAIL_LOOPS] || 0
            perf[WELL_KNOWN_TOTAL] = perf[WELL_KNOWN_PASS] + perf[WELL_KNOWN_FAIL]

            test_meta << {"Job ##{job_id}" => perf}
          else
            Maestro.log.debug "Row is blank, skipping"
          end
        end

        save_output_value('test', test_meta)
        save_output_value('links', url_meta)
      rescue ConfigError, TestAbortError, ApicaAPIError, PermissionsError => e
        @error = e.message
      rescue Exception => e
        @error = "Error executing Apica Tests: #{e.class} #{e}"
        Maestro.log.warn("Error executing Apica Tests: #{e.class} #{e}: " + e.backtrace.join("\n"))
      end

      write_output "\n\nAPICA LOADTEST task complete"
      set_error(@error) if @error
    end

    ###########
    # PRIVATE #
    ###########
    private

    def process_apica_response(state, body)
      # Assumed to be JSON - master rescue will deal with that
      apica_data = JSON.parse(body)

      # Expect the following properties to be present:
      # "Success" true/false
      # "Message" ''/"None" or something meaningful
      msg = apica_data[APICA_KEY_MESSAGE]

      if !msg.nil? && !msg.empty? && msg != 'None'
        # We got a message!
        write_output("\n[#{state}] #{APICA_KEY_MESSAGE} from Apica: '#{msg}'")
      end

      if !apica_data[APICA_KEY_SUCCESS]
        write_output("\n[#{state}] Apica API call failed\nRaw API response:\n------\n#{body}\n------\n")
        raise ApicaAPIError, "Apica API call failed with status #{msg}"
      end

      apica_data
    end

    def get_http(uri)
      # Get appropriate http/https
      # Check for proxy settings
      s = (uri.scheme == 'https')

      proxy_url = ENV[s ? 'https_proxy' : 'http_proxy'] || ENV[s ? 'HTTPS_PROXY' : 'HTTP_PROXY'] || ''
      proxy_uri = nil

      if !proxy_url.empty?
        begin
          proxy_uri = URI.parse(proxy_url)
        rescue Exception
          write_output("\nIgnoring bad proxy URL '#{proxy_url}'")
        end
      end

      http = proxy_uri ? Net::HTTP.new(uri.host, uri.port, proxy_uri.host, proxy_uri.port) : Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = s
      http
    end

    def do_http(path, data, options)
      options = options.merge({:follow_redirect => true})

      # Get URI
      uri = URI.parse @server_url
      escaped_path = URI.escape(path)
      uri = URI.parse("#{@server_url}#{escaped_path}")

      http = get_http(uri)

      # Do the request
      request = yield(uri, data, options)
      request.basic_auth(@user, @password) 

      # Auth debug
      username_s = !@user.empty? ? " with username #{@user}" : ""
      Maestro.log.debug("Performing #{request.method} #{uri}#{username_s}")
#      write_output("\nPerforming #{request.method} #{uri}#{username_s}")

      http.start do |http|
        response = http.request(request)

        case response
        when Net::HTTPSuccess     then 
          return response
        when Net::HTTPRedirection then
          new_url = response['location']

          if options[:follow_redirect]
            # Make sure we don't follow our tail
            redir_options = options.clone
            redir_options[:follow_redirect] = false

            Maestro.log.debug("Redirected to #{new_url}")
            do_get(new_url)
          else
            Maestro.log.debug("Not following redirect to #{new_url}")
            response
          end
        else
          Maestro.log.debug "Error in #{request.method} #{uri}#{username_s}: #{response.code} #{response.message}"

          case response.code
          when 401 then # UNAUTHORIZED
            rause UnauthorizedError, 'Not permitted access (did you specify a user/password?)'
          when 403 then # FORBIDDEN
            raise ForbiddenError, 'User or Password is incorrect'
          else
            write_output("\nError in #{request.method} #{uri}#{username_s}: #{response.code} #{response.message}")
            response.error!
          end
        end
      end
    end

    def do_get(path, options = {})
      do_http(path, nil, options) { |uri, data, options|
        Net::HTTP::Get.new(uri.path)
      }
    end

    def do_post(path, data, options = {})
      do_http(path, data, options) { |uri, data, options|
        request = Net::HTTP::Post.new(uri.path)
        request.add_field('Content-Type', 'application/json')
        request.body = data
        request
      }
    end

    def do_put(path, data, options = {})
      do_http(path, data, options) { |uri, data, options|
        request = Net::HTTP::Put.new(uri.path)
        request.add_field('Content-Type', 'application/json')
        request.body = data
        request
      }
    end
  end
end