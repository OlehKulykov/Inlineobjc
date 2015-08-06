Pod::Spec.new do |s|

# Common settings
  s.name         = "Inlineobjc"
  s.version      = "0.1.4"
  s.summary      = "Inline Objective-C small functions"
  s.description  = <<-DESC
Inline Objective-C small functions
                      DESC
  s.homepage     = "https://github.com/OlehKulykov/Inlineobjc"
  s.license      = { :type => 'MIT', :file => 'LICENSE' }
  s.author       = { "Oleh Kulykov" => "info@resident.name" }
  s.source       = { :git => 'https://github.com/OlehKulykov/Inlineobjc.git', :tag => s.version.to_s, :submodules => "true" }

# Platforms
  s.platform     = :ios, '7.0'
  s.requires_arc = true

# Build  
  s.public_header_files = 'UIImage_Inlineobjc.h',
	'UIColor_Inlineobjc.h',
	'NSData_Inlineobjc.h', 
	'NSData_InlineobjcZip.h',
	'NSDictionary_Inlineobjc.h',
	'NSMutableArray_Inlineobjc.h',
	'NSString_Inlineobjc.h'
  s.source_files = 'InlineobjcDummy.m'
  s.requires_arc = true

end
