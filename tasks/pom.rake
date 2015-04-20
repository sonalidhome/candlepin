require 'builder'
require './tasks/util'

# Buildr does provide some fairly sophisticated POM generation in the buildr/custom_pom
# module.  However, it does not really allow for definition and configuration of Maven
# plugins.  At some point it may be worth taking some code from it as its method of
# resolving all the dependencies is more comprehensive than ours.  It handles adding
# test, and optional dependencies, for example.
module PomTask
  include Candlepin::Util

  class Config
    def initialize(project)
      @project = project
    end

    def enabled?
      !artifacts.nil? && !artifacts.empty?
    end

    attr_writer :artifacts
    def artifacts
      @artifacts ||= []
    end

    attr_writer :pom_parent
    def pom_parent
      @pom_parent ||= PomTask.top_project(@project)
    end

    def provided_dependencies=(val)
      if val.respond_to?(:each)
        @provided_dependencies = val
      else
        @provided_dependencies = [val]
      end
    end

    def provided_dependencies
      @provided_dependencies ||= []
    end

    attr_writer :pom_parent_suffix
    def pom_parent_suffix
      @pom_parent_suffix ||= "-parent"
    end

    attr_writer :create_assembly
    def create_assembly
      @create_assembly ||= true
    end

    # A list of procs that will be executed in the plugin configuration
    # section of the POM.  The proc receives the XML Builder object and
    # the Buildr Project object. Note that the XML Builder object
    # will already be within a plugin element.  Example:
    #
    # p = Proc.new do |xml, project|
    #   xml.groupId("org.apache.maven.plugins")
    #   xml.artifactId("maven-gpg-plugin")
    #   xml.executions do
    #     xml.execution do
    #       xml.id("sign-artifacts")
    #       [...]
    #     end
    #   end
    # end
    #
    # plugin_procs << p
    #
    # It is unlikely that you want to call plugin_procs= as that would
    # clear the default procs that are created to add some essential maven
    # plugins.  Therefore that method is not provided.  If a plugin_procs=
    # method becomes necessary, here is an implementation:
    #
    # def plugin_procs=(val)
    #   if val.respond_to?(:each)
    #     @plugin_procs = val
    #   else
    #     @plugin_procs = [val]
    #   end
    # end
    def plugin_procs
      unless @plugin_procs
        @plugin_procs = []
        default_plugins = [
          "maven-surefire-plugin",
          "maven-assembly-plugin",
          "maven-compiler-plugin",
        ]
        default_plugins.each do |p|
          @plugin_procs << Proc.new do |xml, proj|
            xml.groupId("org.apache.maven.plugins")
            xml.artifactId(p)
          end
        end
      end
      @plugin_procs
    end
  end

  class PomBuilder
    attr_reader :artifact
    attr_reader :dependencies
    attr_reader :project
    attr_reader :config

    def initialize(artifact, project, config)
      @artifact = artifact
      @project = project
      @config = config

      # Filter anything that can't be treated as an artifact
      @dependencies = project.compile.dependencies.select do |dep|
        dep.respond_to?(:to_spec)
      end
      @buffer = ""
      build
    end

    def build
      artifact_spec = artifact.to_hash
      parent_spec = PomTask.as_pom_artifact(@config.pom_parent).to_hash

      # Ugly hack to allow for the fact that the "server" project artifactId is
      # "candlepin" which conflicts with the name of the top-level buildr project
      parent_spec[:id] = "#{parent_spec[:id]}#{@config.pom_parent_suffix}"

      xml = Builder::XmlMarkup.new(:target => @buffer, :indent => 2)
      xml.instruct!
      xml.comment!(" vim: set expandtab sts=4 sw=4 ai: ")
      xml.project(
        "xsi:schemaLocation" => "http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd",
        "xmlns" => "http://maven.apache.org/POM/4.0.0",
        "xmlns:xsi" => "http://www.w3.org/2001/XMLSchema-instance"
      ) do
        xml.modelVersion("4.0.0")

        xml.parent do
          xml.groupId(parent_spec[:group])
          xml.artifactId(parent_spec[:id])
          xml.version(parent_spec[:version])
          project_path = Pathname.new(@project.base_dir)
          parent_path = Pathname.new(@config.pom_parent.base_dir)
          xml.relativePath(parent_path.relative_path_from(project_path).to_s)
        end

        xml.groupId(artifact_spec[:group])
        xml.artifactId(artifact_spec[:id])
        xml.version(artifact_spec[:version])
        xml.packaging(artifact_spec[:type].to_s)

        version_properties = {}

        # Manage version numbers in a properties section
        xml.properties do
          dependencies.each do |dep|
            h = dep.to_hash
            prop_name = "#{h[:group]}-#{h[:id]}.version"
            xml.tag!(prop_name, h[:version])
            version_properties[h] = "${#{prop_name}}"
          end
        end

        xml.dependencies do
          dependencies.each do |dep|
            h = dep.to_hash
            xml.dependency do
              xml.groupId(h[:group])
              xml.artifactId(h[:id])
              xml.version(version_properties[h])

              if @config.provided_dependencies.include?(dep.to_spec)
                xml.scope("provided")
              end

              # We manage all dependencies explicitly and we don't want to drag
              # in any conflicting versions.  For example, we use Guice 3.0 but the
              # Resteasy Guice library has a dependency on Guice 2.0.
              xml.exclusions do
                xml.exclusion do
                  xml.groupId('*')
                  xml.artifactId('*')
                end
              end
            end
          end
        end

        xml.build do
          xml.plugins do
            config.plugin_procs.each do |plugin_proc|
              xml.plugin do
                plugin_proc.call(xml, project)
              end
            end
          end
        end
      end
    end

    def write_pom(destination)
      FileUtils.mkdir_p(File.dirname(destination))
      File.open(destination, "w") { |f| f.write(@buffer) }
    end
  end

  module ProjectExtension
    include Extension

    def pom
      @pom ||= PomTask::Config.new(project)
    end

    first_time do
      desc 'Generate a POM file'
      Project.local_task('pom')
    end

    after_define do |project|
      pom = project.pom
      if pom.enabled?
        project.recursive_task('pom') do
          pom.artifacts.each do |artifact|
            spec = artifact.to_hash
            destination = project.path_to("pom.xml")

            # Special case for when we want to build a POM for just candlepin-api.jar
            if pom.artifacts.length > 1 && spec[:type] != :war
              destination = project.path_to(:target, "#{spec[:id]}-#{spec[:version]}.pom")
            end

            xml = PomBuilder.new(artifact, project, pom)
            xml.write_pom(destination)
            info("POM written to #{destination}")
          end
        end
      end
    end
  end
end

class Buildr::Project
  include PomTask::ProjectExtension
end
