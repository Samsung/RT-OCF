INTERNAL_TOOLS_DIR=File.expand_path(File.dirname(__FILE__))
TOOLS_DIR=File.expand_path(File.join(INTERNAL_TOOLS_DIR, '..'))
IOTIVITY_RT_ROOT=File.expand_path(File.join(TOOLS_DIR, '..'))
UNITY_DIR=File.expand_path(File.join(IOTIVITY_RT_ROOT, 'extlibs', 'CMock', 'vendor', 'unity'))
TEST_REPORT_DIR = File.expand_path(File.join(IOTIVITY_RT_ROOT, 'os', 'linux', 'test', 'bin'))
suppress_error = !ARGV.nil? && !ARGV.empty? && (ARGV[0].upcase == "--SILENT")


begin
  require "#{UNITY_DIR}/auto/unity_test_summary.rb"
  require "#{UNITY_DIR}/auto/colour_reporter.rb"

  results = Dir["#{TEST_REPORT_DIR}/*.result"]
  parser = UnityTestSummary.new
  parser.targets = results
  parser.run

  if ENV['NOCOLOR']
    puts(parser.report)
  else
    report(parser.report)
  end
rescue StandardError => e
  raise e unless suppress_error
end

exit(parser.failures) unless suppress_error
