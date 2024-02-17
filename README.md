# SharpObfuscate

SharpObfuscate transforms a payload into a list of IPv4, IPv6, MAC or UUID strings.

It takes the bytes from a hexadecimal string, a file in the system, a file downloaded from a URL or an ordinary string.

```
SharpObfuscate.exe [OPTION] [PAYLOAD]
```

There are 4 possible values for the option parameter: 
- "ipv4": Get the list of strings in IPv4 address format, like "192.100.1.1"
- "ipv6": Get the list of strings in IPv6 address format, like "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
- "mac": Get the list of strings in MAC address format, like "00-B0-D0-63-C2-26"
- "uuid": Get the list of strings in UUID format, like "550e8400-e29b-41d4-a716-446655440000"

The payload parameter can be a: 
- Hexadecimal value - If it starts with "0x" or "\x" we take the bytes from the string.
  -  Examples: "0xFC4883E4F0E8C00000004151415052", "\xFC\x48\x83\xE4\xF0\xE8\xC0\x00\x00\x00\x41\x51\x41\x50\x52"
- File path - If it is the path of a file in the system, we take the bytes from it.
  - Example: "C:\Windows\System32\calc.exe"
- URL to download a file - If it starts with "http" we download the file and take the bytes from it.
  - Example: "http://127.0.0.1/test.txt"
- String - If no other payload type applies, we take the bytes from the string.

---------------------------------------------------------

## Examples

### Get IPv4 string list from a hexadecimal value in "0x" format

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpobfuscate/Screenshot_5.png)

### Get IPv6 string list from a hexadecimal value in "\x" format

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpobfuscate/Screenshot_6.png)

### Get MAC string list from a file in the system

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpobfuscate/Screenshot_7.png)

### Get UUID string list from a file downloaded from a URL

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/sharpobfuscate/Screenshot_8.png)
