Pod::Spec.new do |s|

# Common settings
  s.name         = "Inlineobjc"
  s.version      = "1.0.1"
  s.summary      = "Inline Objective-C small functions for more stable and safer code"
  s.description  = <<-DESC
Inline Objective-C small functions for more stable and safer code. Few usefull daily functions.
                      DESC
  s.homepage     = "https://github.com/OlehKulykov/Inlineobjc"
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.author       = { "Oleh Kulykov" => "info@resident.name" }
  s.source       = { :git => 'https://github.com/OlehKulykov/Inlineobjc.git', :tag => s.version.to_s }

# Platforms
  s.ios.deployment_target = "7.0"
  s.osx.deployment_target = "10.7"
  s.watchos.deployment_target = '2.0'
  s.tvos.deployment_target = '9.0'

# Build  
  s.source_files = '*.h'
  s.public_header_files = '*.h'
  s.requires_arc = true
  s.libraries    = 'z'
  s.framework = 'CoreFoundation', 'CoreGraphics'
end
