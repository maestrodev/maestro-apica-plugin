# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# 
#  http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

require 'spec_helper'

describe MaestroDev::ApicaWorker do
  BASE_URL = "apica.sample.com/test"
  JOB_ID = "42"
  
  describe '/apica/loadtest' do
    before(:each) do
      Maestro::MaestroWorker.mock!
      @worker = MaestroDev::ApicaWorker.new
      @server_url = "http://#{BASE_URL}"
      @user = 'test'
      @password = 'pass'
#      @worker.stubs(:write_output).with { |v| print "#{v}\n"; 1 }
#      @worker.stubs(:set_error).with { |v| print "#{v}\n @ #{caller}"; 1 }
    end
  
    it 'should complain if config bad' do
      
      workitem = {'fields' => {}}
      @worker.perform(:loadtest, workitem)
      workitem['fields']['__error__'].should include('Error executing Apica Tests: RuntimeError Configuration errors:')
    end

    it "should connect to a remote server and execute a given set of commands" do
      stub_request(:put, "#{@user}:#{@password}@#{BASE_URL}").to_return(:body => "{\"Job id\": #{JOB_ID}, \"Success\": true}")
      stub_request(:get, "#{@user}:#{@password}@#{BASE_URL}/#{JOB_ID}").to_return(:body => '{"Job completed successfully": true, "Success": true}')

      workitem = {'fields' => {'server_url' => @server_url, 'user' => @user, 'password' => @password, 'timeout' => 10, 'command_string' => "bob"}}
      @worker.perform(:loadtest, workitem)
      workitem['fields']['__error__'].should be_nil
      workitem['__output__'].should_not be_nil
#      print JSON.pretty_generate(workitem)
    end
  
    it "should raise an error when it fails to connect to the server" do
      stub_request(:put, "#{@user}:#{@password}@#{BASE_URL}").to_return(:status => 404)

      workitem = {'fields' => {'server_url' => @server_url, 'user' => @user, 'password' => @password, 'timeout' => 10, 'command_string' => "bob"}}
      @worker.perform(:loadtest, workitem)
      workitem['fields']['__error__'].should include('Error: Net::HTTPServerException 404')
    end
  
    it "should raise an error when it fails to connect to the server with wrong username" do
      stub_request(:put, "#{@user}:#{@password}@#{BASE_URL}").to_return(:status => 401, :body => 'Just who do you think you are?')

      workitem = {'fields' => {'server_url' => @server_url, 'user' => @user, 'password' => @password, 'timeout' => 10, 'command_string' => "bob"}}
      @worker.perform(:loadtest, workitem)
      workitem['fields']['__error__'].should include('Error: Net::HTTPServerException 401')
    end
  end
end
