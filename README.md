maestro-apica-plugin
====================

A Maestro Plugin that provides integration with Apica Test Tools

Task Parameters
---------------

* "Server URL"

  A valid URL pointing to the 'selfservice' page for your account.
  The account/customer id is encoded as part of the URL.

* "User"

  Username to access API.  This is same as that used to access Web UI.

* "Password"

  Password to access API.  This is same as that used to access Web UI.

* "Command String"

  (Called 'Command String' for UI layout reasons)
  This is actually a CSV list of tests to run.
  Each line must have two fields, separated by a comma.
  No format adjustment is done, so do not include any extra quotes or spaces.
  Format:
    ConfigurationName,RunnableFileName

* "Comparison History"

  Default: 5
  How many previous tests to compare against.  This seems to be limited to the emailed/online report.

* "Report Mailing List"

  Default: [] (empty)
  A list of email addresses.  As each test completes a test-report will be sent to these addresses.
  Note: One email address per line, use the '+' button to add more addresses.

* "Timeout"

  Default: 900 seconds (15 minutes)
  How long test will be allowed to continue before agent gives up.  Note that the test is not cancelled, and it may eventually complete - we just won't be waiting.
  Note: This value is 'per test'
