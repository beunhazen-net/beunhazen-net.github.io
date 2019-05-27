#!/usr/bin/env ruby
# frozen_string_literal: true

require 'base64'
require 'digest'
require 'openssl'
require 'securerandom'
require 'socket'

# Much larger number to prevent looping from happening
@max   = 100_000_000_000_000_000

# Use a secure random number so tokens cannot be predicted
@seed  = SecureRandom.random_number @max
# Generate a new random key every time we restart the application
@key   = SecureRandom.hex(3)

@flag  = IO.read('flag.txt').chomp
@mutex = Mutex.new

def client_handler(client)
  # Call for PoW
  proof_of_work client

  # Show menu
  client_menu client

  client&.close
end

# Proof of Work function the client must complete
# to ensure our service is not abused DoS'ed.
def proof_of_work(client)
  value = SecureRandom.hex(16)
  work  = Digest::SHA2.hexdigest value
  client.puts "Please provide proof of work for: SHA2(????#{value[4..-1]}) == #{work}"
  client.print '? '
  pow = Digest::SHA2.hexdigest client.gets.chomp
  return true if pow == work

  # Show source as implementation reference if PoW fails
  client.puts File.read __FILE__
  client&.close
end

def client_menu(client)
  client.puts <<~ENDOFMENU
    1: Generate OTP token
    2: Validate OTP token
    3: Quit
  ENDOFMENU
  client.print '? '
  client_menu_handler client, client.gets.chomp.to_i
end

def client_menu_handler(client, input)
  case input
  when 1
    show_token client
  when 2
    validate_token client
  else
    client&.close
  end
end

# Generate token using cryptographically secure hash function
def next_token(seed = @seed.to_s, salt = SecureRandom.random_bytes(4), algo = 'SHA256', token = '')
  @mutex.synchronize do
    salt      = Base64.strict_encode64 salt
    timestamp = (Time.now.to_i / 100) * 100
    hmac      = OpenSSL::HMAC.hexdigest(algo, @key, "#{salt}:#{seed}:#{algo}:#{timestamp}")
    token     = "#{salt}:#{algo}:#{hmac}"
    increment
  end
  Base64.strict_encode64 token
end

def show_token(client)
  client.puts next_token
  client&.close
end

def validate_token(client)
  client.puts 'Please provide your OTP token'
  client.print '? '

  input = client.gets.chomp
  begin
    input    = Base64.decode64(input)
    input    = input.split(':')
    input[1] = Base64.decode64(input[1])
  rescue StandardError => _e
    client.puts 'Failed to decode input'
    return
  end

  if input[0].to_i < @seed - 1
    client.puts 'Token replay attack detected!'
    client&.close
    return
  end

  hmac = Base64.decode64(next_token((@seed - 1).to_s, input[1], input[2])).split(':').last

  if input[3] == hmac
    client.puts @flag
  else
    client.puts 'Invalid token'
  end
  client&.close
end

# Pull manipulation of global state out to separate
# function for scaling, performance and security reasons.
def increment
  if @seed < @max
    @seed += 1
  else
    @seed = 0
  end
end

# Start up the server
server = TCPServer.new 'OTP'.to_i(36) + 2
loop do
  Thread.fork(server.accept) do |client|
    client_handler client
  rescue StandardError => e
    # Just log errors to stdout
    puts "Error: #{e}"
  ensure
    client&.close
  end
end
