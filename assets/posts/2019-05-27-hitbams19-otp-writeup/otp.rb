#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'securerandom'
require 'socket'

# Prevent number from growing out of control over time
@max   = 100_000_000
# Use a secure random number so tokens cannot be predicted
@seed  = SecureRandom.random_number @max

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
def next_token(token = '')
  @mutex.synchronize do
    token = Digest::SHA2.hexdigest @seed.to_s
    if @seed < @max
      @seed += 1
    else
      @seed = 0
    end
  end
  token[0..16]
end

def show_token(client)
  client.puts next_token
  client&.close
end

def validate_token(client)
  client.puts 'Please provide your OTP token'
  client.print '? '
  if client.gets.chomp == next_token
    client.puts @flag
  else
    client.puts 'Invalid token'
  end
  client&.close
end

# Start up the server
server = TCPServer.new 'OTP'.to_i 36
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
