# frozen_string_literal: true

require "open3"
require "securerandom"
require "shellwords"
require "sinatra/base"

class App < Sinatra::Base
  before do
    request.env["HTTP_X_REQUEST_ID"] ||= SecureRandom.hex(4)
  end

  get "/" do
    hostname = params.fetch("q", nil)

    if hostname.nil?
      content_type "text/plain"
      halt "No hostname"
    end

    # testssl.sh always prints to stdout
    # abuse stderr to get HTML output to stream instead of file
    escaped_hostname = Shellwords.escape(hostname)
    command_parts = [
      "testssl.sh",
      "--quiet",
      quick? ? "--headers" : nil, # something quick
      "--htmlfile",
      "/dev/stderr",
      escaped_hostname,
    ].compact
    command = Shellwords.join(command_parts)

    log "cli_agent? #{cli_agent?} command=#{command.inspect}"

    status 200
    content_type "text/html"

    stdin, stdout, stderr, wait_thr = Open3.popen3(command)

    stream_body = lambda do |output_stream|
      output_thread = Thread.new do
        begin
          loop do
            console_output = stdout.readpartial(8192)
            html_output = stderr.readpartial(8192)

            print console_output if console_log?

            if cli_agent?
              output_stream.print(console_output)
            else
              output_stream.print(html_output)
            end
          rescue Puma::ConnectionError => e
            debug "output_thread #{e.inspect}"
            log "Client disconnected"

            Process.kill("KILL", wait_thr.pid)

            break
          end
        rescue EOFError => e
          debug "output_thread #{e.inspect}"
        end
      end

      output_thread.run

      wait_thr.join
      output_thread.join

      stdin.close
      stdout.close
      stderr.close
      log "Completed"
    ensure
      output_stream.close
    end

    body stream_body
  end

  helpers do
    def quick?
      true? :QUICK
    end

    def debug?
      true? :DEBUG
    end

    def console_log?
      true? :CONSOLE_LOG
    end

    def cli_agent?
      %w(curl wget).any? { |agent| request.user_agent.include?(agent) }
    end

    def debug(str)
      return unless debug?

      log str
    end

    def true?(var_name, default: "false")
      %w(1 true).include?(ENV.fetch(var_name.to_s, default.to_s))
    end

    def log(str)
      req_id = request.env.fetch("HTTP_X_REQUEST_ID")
      puts "[#{req_id}] #{str}"
    end
  end
end
