
# Copyright 2022 Marek Küthe
# GNU GPLv3

# This program can transfer a file from one device to another.
# For this it uses a tunnel, a backup tunnel each of a length of one hop.
# This can be changed in the source code.
# Requires gems: base32, base_x

require "base64"
require "base32"
require "base_x"
require "openssl"
require "securerandom"
require_relative "samapi.rb"

def set_status status
  if status[0]
    puts "Status = OK"
  else
    puts "Error = #{status[-1][:args].values.join " "}"
    puts "About!"
    exit!
  end
end

def privkey_to_hash priv_key
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
  
  return hash
end

def encode_hash hash, passwd = "\0\0\0\0\0"
  passwd.length == 5 or raise ArgumentError.new("Passwd must have length 5")
  
  bin = passwd + hash
  checksum = bin.bytes.reduce(0, :+) % 10
  checksum_bin = [checksum].pack("C")
  bin = checksum_bin + bin
  b36 = BaseX.encode(bin, numerals: "0123456789abcdefghijkmnopqrstuvwxyz").chars

  return b36.each_slice(4).map(&:join)
end

def decode_hash codes
  bin = BaseX.decode(codes, numerals: "0123456789abcdefghijkmnopqrstuvwxyz")
  
  checksum_bin = bin[0]
  checksum = checksum_bin.unpack("C")[0]
  passwd = bin[1...6]
  hash = bin[6..-1]
  calc_checksum = bin[1..-1].bytes.reduce(0, :+) % 10
  
  return [checksum == calc_checksum, passwd, hash]
end

def hash_to_b32 hash
  return Base32.encode(hash).tr("=", "").downcase + ".b32.i2p"
end

def display_transfercode code
  tf = (code.map { |code_block|
    code_block.upcase
  }).join " "

  puts "TRANSFER CODE: TF #{tf}"
end

if ARGV[0]
  if ! File.readable? ARGV[0]
    puts "File to send unreadable."
    exit!
  end
  
  puts "Preparing file for sending (reading file into memory)..."
  cnt = File.read ARGV[0]
  
  control = SamApi.new
  set_status control.handshake
  comm = SamApi.new
  set_status comm.handshake

  passwd = SecureRandom.random_bytes(5)
  
  server = TCPServer.new "127.0.0.1", 0
  Thread.new do
    loop {
      Thread.new(server.accept) { |socket|
        in_passwd = socket.read 5
        socket.puts File.basename ARGV[0]
        if in_passwd == passwd
          socket.write cnt
        end
        socket.close
      }
    }
  end

  host = server.addr[3]
  port = server.addr[1]

  res = control.session_create(
    "STYLE" => "STREAM",
    "ID" => "BeamBotSender",
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
    "ID" => "BeamBotSender",
    "PORT" => port,
    "HOST" => host,
    "SILENT" => true
  )

  hash = privkey_to_hash priv_key
  transfercode = encode_hash hash, passwd
  display_transfercode transfercode

  loop {
    control.check_ping
    comm.check_ping
    status = control.send_ping and comm.send_ping
    if ! status
      puts "Warning = No ping"
    end
    sleep 10
  }
else
  control = SamApi.new
  set_status control.handshake

  res = control.session_create(
    "STYLE" => "STREAM",
    "ID" => "BeamBotRecipent",
    "DESTINATION" => "TRANSIENT",
    "SIGNATURE_TYPE" => "EdDSA_SHA512_Ed25519",
    "inbound.length" => "1",
    "outbound.length" => "1",
    "inbound.quantity" => "1",
    "outbound.quantity" => "1",
    "inbound.backupQuantity" => "1",
    "outbound.backupQuantity" => "1"
  )
  set_status res
  
  print "Transfer code: TF "
  STDOUT.flush
  tf = gets.chomp
  tf = tf.tr(" ", "").downcase
  res = decode_hash tf
  if ! res[0]
    puts "Warning = Mismatch checksum"
  end
  passwd = res[1]
  hash = res[2]
  b32 = hash_to_b32 hash
  lookup_result = control.naming_lookup b32
  set_status lookup_result
  b64 = lookup_result[1]
  
  control.check_ping

  comm = SamApi.new
  set_status comm.handshake
  stream = comm.stream_connect(
    "ID" => "BeamBotRecipent",
    "DESTINATION" => b64
  )
  set_status stream
  
  puts "Connected"
  socket = stream[1]
  puts "Authenticating..."
  socket.write passwd
  socket.flush
  if socket.closed?
    puts "Authentication failed"
  else
    puts "Authentication successful"
    puts "Receive file..."
    filename = socket.gets.chomp
    cnt = socket.read
    File.write "recived_#{filename}", cnt
  end
end
