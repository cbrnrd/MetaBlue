##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'bluetooth'

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Bluetooth Scan',
      'Description'    => %q{
        This module scans the area around you for listening bluetooth devices.
      },
      'Author'         => [ 'Carter Brainerd <cbrnrd>' ],
      'License'        => MSF_LICENSE
    ))

  end

  def run

    print_status('Beginning scan...')

    devices = Bluetooth.scan

    devices.each do |id|
      print_good("Device found: #{id}")
    end
  end

end
