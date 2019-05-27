#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'securerandom'
require 'socket'

# Much larger number to prevent looping from happening
@max   = 100_000_000_000_000_000
# Use a secure random number so tokens cannot be predicted
@seed  = SecureRandom.random_number @max
# Use a secret key as part of the token to make prediction impossible
@key   = IO.read('secret.txt').chomp

@flag  = IO.read('flag.txt').chomp
@mutex = Mutex.new

def client_handler(client, seed)
  # Call for PoW
  proof_of_work client

  # Show menu
  client_menu client, seed

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

def client_menu(client, seed)
  client.puts <<~ENDOFMENU
    1: Generate OTP token
    2: Validate OTP token
    3: Quit
  ENDOFMENU
  client.print '? '
  client_menu_handler client, client.gets.chomp.to_i, seed
end

def client_menu_handler(client, input, seed)
  case input
  when 1
    show_token client, seed
  when 2
    validate_token client, seed
  else
    client&.close
  end
end

# Generate token using cryptographically secure hash function
def next_token(token = '')
  @mutex.synchronize do
    token = Digest::SHA2.hexdigest token
  end
  token[0..16]
end

def show_token(client, seed)
  client.puts next_token(seed)
  client&.close
end

def validate_token(client, seed)
  client.puts 'Please provide your OTP token'
  client.print '? '
  if client.gets.chomp == next_token(seed)
    client.puts @flag
  else
    client.puts 'Invalid token'
  end
  client&.close
end

# Pull manipulation of global state out to separate
# function for scaling, performance and security reasons.
def increment
  @mutex.synchronize do
    if @seed < @max
      @seed += 1
    else
      @seed = 0
    end
  end
end

# Start up the server
server = TCPServer.new 'OTP'.to_i(36) + 1
loop do
  Thread.fork(server.accept) do |client|
    client_handler client, "#{@key}#{@seed}"
  rescue StandardError => e
    # Just log errors to stdout
    puts "Error: #{e}"
  ensure
    # Always increment the seed so if anything
    # fails we will not leave a predictable token.
    increment
    client&.close
  end
end
