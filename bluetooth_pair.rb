##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'bluetooth'

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Bluetooth Simple Pair',
      'Description'    => %q{
        This module simply pairs over Bluetooth with a target device.
      },
      'Author'         => [ 'Carter Brainerd <cbrnrd>' ],
      'License'        => MSF_LICENSE
    ))

    register_options([
      OptString.new('MAC_ADDR', [true, 'The MAC address to pair to'])
      ])

  end

  VALID_MAC = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/  # TODO test this more

  def run

    address = datastore['MAC_ADDR']

    # Check MAC
    if address =~ VALID_MAC
      print_error("#{address} is not a valid MAC address!")
      return
    end

    device = Bluetooth::Device.new address

    device.pair_confirmation do |num|
      vprint_status('Addempting initial connection, message incoming.')
      print_status("The device should say #{num}")
      true
    end

    paired = device.pair ? true : false

    if paired
      print_good('Pairing successful!')
    else
      print_error('Pairing unsuccessful.')
    end

  end

end
