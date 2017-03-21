require_relative 'rule'
require_relative 'custom_rule_loader'
require_relative 'rule_registry'
require_relative 'profile_loader'
require_relative 'model/cfn_model'
require_relative 'result_view/simple_stdout_results'
require_relative 'result_view/json_results'
require_relative 'result_view/rules_view'
require 'tempfile'

class CfnNag
  include Rule

  def initialize(profile_definition: nil)
    @warning_registry = []
    @violation_registry = []
    @rule_registry = RuleRegistry.new
    @custom_rule_loader = CustomRuleLoader.new(@rule_registry)
    @profile_definition = profile_definition
  end

  def dump_rules(rule_directories: [])
    validate_extra_rule_directories(rule_directories)

    dummy_cfn = <<-END
      {
        "Resources": {
          "resource1": {
            "Type" : "AWS::EC2::DHCPOptions",
            "Properties": {
              "DomainNameServers" : [ "10.0.0.1" ]
            }
          }
        }
      }
    END

    Tempfile.open('tempfile') do |dummy_cfn_template|
      dummy_cfn_template.write dummy_cfn
      dummy_cfn_template.rewind
      audit_file(input_json_path: dummy_cfn_template.path,
                 rule_directories: rule_directories)
    end

    profile = nil
    unless @profile_definition.nil?
      profile = ProfileLoader.new(@rule_registry).load(profile_definition: @profile_definition)
    end

    RulesView.new.emit(@rule_registry, profile)
  end

  def audit(input_file_path:,
            rule_directories: [],
            output_format:'txt')
    validate_extra_rule_directories(rule_directories)

    aggregate_results = audit_results input_file_path: input_file_path,
                                      output_format: output_format,
                                      rule_directories: rule_directories.flatten

    aggregate_results.inject(0) { |total_failure_count, results| total_failure_count + results[:file_results][:failure_count] }
  end

  def audit_results(input_file_path:,
                    output_format:'txt',
                    rule_directories: [])

    templates = discover_templates(input_file_path)

    aggregate_results = []
    templates.each do |template|
      aggregate_results << {
          filename: template,
          file_results: audit_file(input_file_path: template,
                                   rule_directories: rule_directories)
      }
    end

    render_results(aggregate_results: aggregate_results,
                   output_format: output_format)

    aggregate_results
  end

  def self.configure_logging(opts)
    logger = Logging.logger['log']
    if opts[:debug]
      logger.level = :debug
    else
      logger.level = :info
    end

    logger.add_appenders Logging.appenders.stdout
  end

  def audit_template(input_file:,
                     rule_directories: [])
    @stop_processing = false
    @violations = []

    # Attempt to parse the input file as JSON
    is_json, json_error = legal_json?(input_file)
    input_json = input_file if is_json

    # Input file isn't JSON, attempt parsing it as YAML
    unless is_json
      is_yaml, yaml_error = legal_yaml?(input_file) unless is_json
      # Input file is YAML - convert it to JSON representation. Tool's major
      # functionality is bound to JSON/jq heavily, thus reimplementing it in
      # YAML-specific way would be a major rewrite.
      input_json = YAML.load(input_file).to_json if is_yaml
    end

    # Report the fact input file is neither JSON or YAML along with
    # corresponding parsing error, to make troubleshooting easier
    unless is_yaml or is_json
      @violations << Violation.new(id: 'FATAL',
                                   type: Violation::FAILING_VIOLATION,
                                   message: 'not even legit JSON nor YAML',
                                   violating_code: "Input: #{input_file}\n\n" \
                                           "Parsing as JSON: #{json_error}\n" \
                                           "Parsing as YAML: #{yaml_error}")
      @stop_processing = true
    end

    generic_json_rules(input_json, rule_directories) unless @stop_processing == true

    @violations += custom_rules input_json unless @stop_processing == true

    @violations = filter_violations_by_profile @violations unless @stop_processing == true

    {
      failure_count: Rule::count_failures(@violations),
      violations: @violations
    }
  end

  private

  def filter_violations_by_profile(violations)
    profile = nil
    unless @profile_definition.nil?
      profile = ProfileLoader.new(@rule_registry).load(profile_definition: @profile_definition)
    end

    violations.reject do |violation|
      not profile.nil? and not profile.execute_rule?(violation.id)
    end
  end

  def validate_extra_rule_directories(rule_directories)
    rule_directories.flatten.each do |rule_directory|
      fail "Not a real directory #{rule_directory}" unless File.directory? rule_directory
    end
  end


  def render_results(aggregate_results:,
                     output_format:)
    results_renderer(output_format).new.render(aggregate_results)
  end

  def audit_file(input_file_path:,
                 rule_directories:)
    audit_template(input_file: IO.read(input_file_path),
                   rule_directories: rule_directories)
  end

  def discover_templates(input_file_path)
    if ::File.directory? input_file_path
      templates = find_templates_in_directory(directory: input_file_path)
    elsif ::File.file? input_file_path
      templates = [input_file_path.path]
    else
      fail "#{input_file_path} is not a proper path"
    end
    templates
  end

  def find_templates_in_directory(directory:,
                                  cfn_extensions: %w(json yaml template))

    templates = []
    cfn_extensions.each do |cfn_extension|
      templates += Dir[File.join(directory, "**/*.#{cfn_extension}")]
    end
    templates
  end

  def results_renderer(output_format)
    registry = {
      'txt' => SimpleStdoutResults,
      'json' => JsonResults
    }
    registry[output_format]
  end

  def legal_json?(input_json)
    begin
      JSON.parse(input_json)
      [ true, nil ]
    rescue JSON::ParserError => ex
      return [ false, ex.message ]
    end
  end

  def legal_yaml?(input_yaml)
    begin
      return false unless YAML.parse(input_yaml)
      [ true, nil ]
    rescue Psych::SyntaxError => ex
      return [ false, ex.message ]
    end
  end

  def command?(command)
    not system("#{command} > /dev/null 2>&1").nil?
  end

  def generic_json_rules(input_json, rule_directories)
    unless command? 'jq'
      fail 'jq executable must be available in PATH'
    end
    rules = Dir[File.join(__dir__, 'json_rules', '*.rb')].sort

    rules.each do |rule_file|
      @input_json = input_json
      eval IO.read(rule_file)
    end

    rule_directories.each do |rule_directory|
      rules = Dir[File.join(rule_directory, '*.rb')].sort

      rules.each do |rule_file|
        @input_json = input_json
        eval IO.read(rule_file)
      end
    end
  end

  def custom_rules(input_json)
    @custom_rule_loader.custom_rules(input_json)
  end
end
