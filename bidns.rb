# frozen_string_literal: true

require 'logger'
require 'async/dns'
require_relative 'chnroutes_matcher'

class BIDNSServer < Async::DNS::Server
  def initialize
    logger = Logger.new(File.expand_path('bidns.log', File.dirname(__FILE__)))
    logger.level = :info
    STDERR.reopen File.expand_path('bidns.log', File.dirname(__FILE__)), 'w+'
    super([[:udp, '127.0.0.1', 53]], logger: logger)

    @default_dns_ttl = 120
    @dns_cache = {}
    @chnroutes_matcher = ChnroutesMatcher.new(File.expand_path('chnroutes.txt', File.dirname(__FILE__)))
    @local_resolver = Async::DNS::Resolver.new([[:udp, '114.114.114.114', 53]])
    @remote_resolver = Async::DNS::Resolver.new([[:udp, '127.0.0.1', 5300]])
  end

  def run
    @logger.info "Starting Async::DNS server (v#{Async::DNS::VERSION})..."

		Async::Reactor.run do |task|
			fire(:setup)

			Async::IO::Endpoint.each(@endpoints) do |endpoint|
        bind_endpoint(task, endpoint)
			end

			fire(:start)
		end
  end

  def process(name, resource_class, transaction)
    cache_item = @dns_cache["#{name}:#{resource_class}"]

    if cache_item && cache_item[:invalid_at] > Time.now.utc.to_i
      logger.info "#{name} #{resource_class} -> FROM CACHE"
      transaction.response.ra = 1
      transaction.response.merge!(cache_item[:data])
      return
    end

    local_res = transaction.passthrough(@local_resolver)

    if local_res
      resolved_ips = []
      min_ttl = @default_dns_ttl
      local_res.answer.each do |layer|
        layer.each do |item|
          if item.respond_to?(:address)
            ipaddr = item.address.to_s
            resolved_ips << ipaddr unless ipaddr == '0.0.0.0'
          end
          if item.respond_to?(:ttl) && item.ttl > 0
            min_ttl = item.ttl
          end
        end
      end
      resolved_ips.uniq!
      logger.info "#{name} #{resource_class} -> #{resolved_ips.join(', ')} (TTL = #{min_ttl})"
      if resource_class == Resolv::DNS::Resource::IN::AAAA || (!resolved_ips.empty? && resolved_ips.all? { |ip| @chnroutes_matcher.ip_match?(ip) })
        logger.info "#{name} #{resource_class} -> LOCAL"
        transaction.response.ra = 1
        transaction.response.merge!(local_res)
        @dns_cache["#{name}:#{resource_class}"] = {
          data: local_res,
          invalid_at: Time.now.utc.to_i + min_ttl
        }
        return
      end
    end

    remote_res = transaction.passthrough(@remote_resolver)

    if remote_res
      min_ttl = @default_dns_ttl
      remote_res.answer.each do |layer|
        layer.each do |item|
          if item.respond_to?(:ttl) && item.ttl > 0
            min_ttl = item.ttl
          end
        end
      end
      logger.info "#{name} #{resource_class} -> REMOTE (TTL = #{min_ttl})"
      transaction.response.ra = 1
      transaction.response.merge!(remote_res)
      @dns_cache["#{name}:#{resource_class}"] = {
        data: remote_res,
        invalid_at: Time.now.utc.to_i + min_ttl
      }
    elsif local_res
      logger.info "#{name} #{resource_class} -> FALLBACK TO LOCAL"
      transaction.response.ra = 1
      transaction.response.merge!(local_res)
      return
    else
      transaction.fail!(:ServFail)
    end
  end

  private

  def bind_endpoint(task, endpoint)
    task.async do
      endpoint.bind do |socket|
        case socket.type
        when Socket::SOCK_DGRAM
          @logger.info "<> Listening for datagrams on #{socket.local_address.inspect}"
          guard_socket_error(task, endpoint) { Async::DNS::DatagramHandler.new(self, socket).run }
        when Socket::SOCK_STREAM
          @logger.info "<> Listening for connections on #{socket.local_address.inspect}"
          guard_socket_error(task, endpoint) { Async::DNS::StreamHandler.new(self, socket).run }
        else
          raise ArgumentError.new("Don't know how to handle #{address}")
        end
      end
    end
  end

  def guard_socket_error(task, endpoint)
    yield
  rescue EOFError
    @logger.warn "<> EOF: #{endpoint}"
    bind_endpoint(task, endpoint)
  rescue Errno::ECONNRESET => error
    @logger.warn "<> ECONNRESET: #{endpoint}"
    bind_endpoint(task, endpoint)
  rescue Errno::EPIPE
    @logger.warn "<> EPIPE: #{endpoint}"
    bind_endpoint(task, endpoint)
  end
end

server = BIDNSServer.new
server.run
