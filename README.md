# Peach-PCBC-Transform
DES PCBC Transform for Peach Fuzzer

This is a modified DES CBC function to act like PCBC and produce correct encrypted and decrypted results.

# Info
This project depends on the NuGet Library:
OpenSSL.NET x32

and on the Peach.Core.dll version 3.1.124.0

# Binary Install
To get started, copy the files "DES_PCBC.dll" and "ManagedOpenSsl.dll" to your local peach root directory

# Source Compile
I compiled the source with Sharpdevelop v5, normally you should be able to just clone this repository and compile it yourself.
After that copy the files "DES_PCBC.dll" and "ManagedOpenSsl.dll" to your local peach root directory

# Usage
After you have added the needed files to your peach directory you should be able to use the transform command like this:
```
	<DataModel name="request">
		<XmlElement name="mytest" elementName="test" mutable="false">
			<Transformer class="DES_PCBC">
				<Param name="Key" value="ABCDEF0123456789"/>
				<Param name="IV" value="ABCDEF0123456789" />
			</Transformer>	

			<XmlElement name="xmlstart" elementName="start" mutable="false">
				<String value="Blah XMLBattery Failure"/>
			</XmlElement>
		</XmlElement>
	</DataModel>
```