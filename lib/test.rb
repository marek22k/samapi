
# Copyright 2022 Marek Küthe
# GNU GPLv3

# Example script that creates a mini HTTP server
# that responds to every request"Hello World!" in text/plain.

require "base64"
require "base32"
require_relative "samapi.rb"

# Returns the status. Aborts execution of the program if an error occurs.
# @param status [Hash]
def set_status status
  if status[0]
    puts "Status = OK"
  else
    puts "Error = #{status[-1][:args].values.join " "}"
    puts "About!"
    exit!
  end
end

# Converts a private key to a base32 address
#
# @param priv_key [String] base64 encoded private key
# @return [String]
def privkey_to_b32 priv_key
  priv_key = priv_key.tr "-~", "+/"
  # conversion of base64 alphabet from i2p to standard
  
  priv_bin = Base64.decode64 priv_key
  # decode the private key
  
  cert_len = priv_bin[385...387].unpack("S>")[0]
  # determining the length of the certificate, others are constants for this case
  pub_len = 256 + 128 + 1 + 2 + cert_len
  # see https://geti2p.net/spec/common-structures#keysandcert
  # calculation of the length of the public part / destination
  
  hash = OpenSSL::Digest::SHA256.digest priv_bin[0...pub_len]
  b32 = Base32.encode(hash).tr("=", "").downcase + ".b32.i2p"
  
  return b32
end

control = SamApi.new
set_status control.handshake
comm = SamApi.new
set_status comm.handshake

server = TCPServer.new "127.0.0.1", 0
Thread.new do
  loop {
    Thread.new(server.accept) { |socket|
      socket.puts <<HEADER
HTTP/1.1 200 OK
Content-Type: text/plain
Connection: Closed

Hello World!
HEADER
      socket.close
    }
  }
end

host = server.addr[3]
port = server.addr[1]

res = control.session_create(
  "STYLE" => "STREAM",
  "ID" => "HelloWorldBot",
  "DESTINATION" => "TRANSIENT",
  "SIGNATURE_TYPE" => "EdDSA_SHA512_Ed25519",
  "inbound.length" => "1",
  "outbound.length" => "1",
  "inbound.quantity" => "1",
  "outbound.quantity" => "1",
  "inbound.backupQuantity" => "1",
  "outbound.backupQuantity" => "1"
)
priv_key = res[1]
set_status res

set_status comm.stream_forward(
  "ID" => "HelloWorldBot",
  "PORT" => port,
  "HOST" => host,
  "SILENT" => true
)

b32 = privkey_to_b32 priv_key
puts "Address: #{b32}"

loop {
  puts "Check pings..."
  control.check_ping
  comm.check_ping
  sleep 10
}
