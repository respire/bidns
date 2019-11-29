# frozen_string_literal: true

require 'ipaddr'
require 'set'

class ChnroutesMatcher
  def initialize(chnroutes_path)
    @dict = build_dict(chnroutes_path)
  end

  def ip_match?(ip)
    ip = IPAddr.new(ip)
    candidates = @dict[ip.hton[0]]
    if candidates
      !candidates.index { |ipr| ipr.include?(ip) }.nil?
    else
      !@dict['escape'].index { |ipr| ipr.include?(ip) }.nil?
    end
  end

  private

  def build_dict(chnroutes_path)
    chnroutes = File.read(chnroutes_path)
    chnroutes = chnroutes.split("\n")
    chnroutes.select! { |row| row.start_with?(/\d/) }
    dict = { 'escape' => [] }
    chnroutes.each do |row|
      _, mask = row.split('/')
      mask = mask.to_i
      ip = IPAddr.new(row)
      if mask <= 24
        fb = ip.hton[0]
        dict[fb] ||= []
        dict[fb] << ip.freeze
      else
        dict['escape'] << ip.freeze
      end
    end
    dict.each_value(&:freeze)
    dict.freeze
  end
end
