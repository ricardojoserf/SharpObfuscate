using System;
using System.Linq;
using System.Collections.Generic;
using System.IO;

namespace SharpObfuscate
{
    internal class Program
    {
        public static byte[] ToByteArray(String hexString)
        {
            // In case the string length is odd
            if (hexString.Length % 2 == 1) {
                Console.WriteLine("[-] Hexadecimal value length is odd, adding a 0.");
                hexString += "0"; 
            }
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }


        public static byte[] downloadFromUrl(string url)
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            using (System.Net.WebClient myWebClient = new System.Net.WebClient())
            {
                try
                {
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    byte[] buf = myWebClient.DownloadData(url);
                    return buf;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    Environment.Exit(0);
                    return null;
                }
            }
        }


        public static bool OnlyHexInString(string test)
        {
            return System.Text.RegularExpressions.Regex.IsMatch(test, @"\A\b[0-9a-fA-F]+\b\Z");
        }


        public static byte[] getPayload(String payload_str)
        {
            byte[] buf = { };
            if (payload_str.Length < 4)
            {
                Console.WriteLine("[-] Payload is too small. Exiting...");
                Environment.Exit(0);
            }

            // Payload from url, http or https
            else if (payload_str.Substring(0, 4) == "http")
            {
                Console.WriteLine("[+] Getting payload from url: " + payload_str);
                buf = downloadFromUrl(payload_str);
            }

            // Hexadecimal payload
            else if (payload_str.Substring(0, 2) == "0x" || payload_str.Substring(0, 2) == "\\x")
            {
                Console.WriteLine("[+] Getting payload from hexadecimal value.");
                payload_str = payload_str.Replace("0x", "");
                payload_str = payload_str.Replace("\\x", "");
                if (OnlyHexInString(payload_str))
                {
                    buf = ToByteArray(payload_str);
                }
            }

            // Bytes from a file
            else if (File.Exists(payload_str)) {
                Console.WriteLine("[+] Getting payload from file.");
                buf = File.ReadAllBytes(payload_str);
            }

            // Byte array from string
            else
            {
                Console.WriteLine("[+] Getting payload from the string.");
                buf = System.Text.Encoding.ASCII.GetBytes(payload_str);
            }

            return buf;
        }


        static string getIPv4(int a, int b, int c, int d)
        {
            string ip_addr = a.ToString() + "." + b.ToString() + "." + c.ToString() + "." + d.ToString();
            return ip_addr;
        }


        static List<string> encodeIPv4(byte[] byte_arr)
        {
            List<string> string_list = new List<string>();
            // Resize to get a length multiple of 4
            if (byte_arr.Length % 4 != 0)
            {
                int padding_needed = 4 - (byte_arr.Length % 4);
                Array.Resize(ref byte_arr, byte_arr.Length + padding_needed);
            }
            // Every 4 bytes generate a IPv4 address in string format
            for (var i = 0; i < byte_arr.Length; i++)
            {
                if (i % 4 == 0)
                {
                    string ip_addr = getIPv4(byte_arr[i], byte_arr[i + 1], byte_arr[i + 2], byte_arr[i + 3]);
                    string_list.Add(ip_addr);
                }
            }
            return string_list;
        }


        static string getIPv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p)
        {
            string ip_addr = a.ToString("X2") + b.ToString("X2") + ":" + c.ToString("X2") + d.ToString("X2") + ":";
            ip_addr += e.ToString("X2") + f.ToString("X2") + ":" + g.ToString("X2") + h.ToString("X2") + ":";
            ip_addr += i.ToString("X2") + j.ToString("X2") + ":" + k.ToString("X2") + l.ToString("X2") + ":";
            ip_addr += m.ToString("X2") + n.ToString("X2") + ":" + o.ToString("X2") + p.ToString("X2");
            return ip_addr;
        }


        static List<string> encodeIPv6(byte[] byte_arr)
        {
            List<string> string_list = new List<string>();
            // Resize to get a length multiple of 16
            if (byte_arr.Length % 16 != 0)
            {
                int padding_needed = 16 - (byte_arr.Length % 16);
                Array.Resize(ref byte_arr, byte_arr.Length + padding_needed);
            }
            // Every 16 bytes generate a IPv6 address in string format
            for (var i = 0; i < byte_arr.Length; i++)
            {
                if (i % 16 == 0)
                {
                    string ip_addr = getIPv6(
                        byte_arr[i], byte_arr[i + 1], byte_arr[i + 2], byte_arr[i + 3],
                        byte_arr[i + 4], byte_arr[i + 5], byte_arr[i + 6], byte_arr[i + 7],
                        byte_arr[i + 8], byte_arr[i + 9], byte_arr[i + 10], byte_arr[i + 11],
                        byte_arr[i + 12], byte_arr[i + 13], byte_arr[i + 14], byte_arr[i + 15]
                        );
                    string_list.Add(ip_addr);
                }
            }
            return string_list;
        }


        static string getMAC(int a, int b, int c, int d, int e, int f)
        {
            string ip_addr = a.ToString("X2") + "-" + b.ToString("X2") + "-" + c.ToString("X2") + "-";
            ip_addr += d.ToString("X2") + "-" + e.ToString("X2") + "-" + f.ToString("X2");
            return ip_addr;
        }


        static List<string> encodeMAC(byte[] byte_arr)
        {
            List<string> string_list = new List<string>();
            // Resize to get a length multiple of 6
            if (byte_arr.Length % 6 != 0)
            {
                int padding_needed = 6 - (byte_arr.Length % 6);
                Array.Resize(ref byte_arr, byte_arr.Length + padding_needed);
            }
            // Every 6 bytes generate a MAC address in string format
            for (var i = 0; i < byte_arr.Length; i++)
            {
                if (i % 6 == 0)
                {
                    string ip_addr = getMAC(byte_arr[i], byte_arr[i + 1], byte_arr[i + 2], byte_arr[i + 3], byte_arr[i + 4], byte_arr[i + 5]);
                    string_list.Add(ip_addr);
                }
            }
            return string_list;
        }


        static string getUUID(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p)
        {
            string ip_addr = d.ToString("X2") + c.ToString("X2") + b.ToString("X2") + a.ToString("X2") + "-"; // Little endian
            ip_addr += f.ToString("X2") + e.ToString("X2") + "-"; // Little endian
            ip_addr += h.ToString("X2") + g.ToString("X2") + "-"; // Little endian
            ip_addr += i.ToString("X2") + j.ToString("X2") + "-"; // Big endian
            ip_addr += k.ToString("X2") + l.ToString("X2") + m.ToString("X2") + n.ToString("X2") + o.ToString("X2") + p.ToString("X2"); // Big endian
            return ip_addr;
        }


        static List<string> encodeUUID(byte[] byte_arr)
        {
            List<string> string_list = new List<string>();
            // Resize to get a length multiple of 16
            if (byte_arr.Length % 16 != 0)
            {
                int padding_needed = 16 - (byte_arr.Length % 16);
                Array.Resize(ref byte_arr, byte_arr.Length + padding_needed);
            }
            // Every 16 bytes generate a UUID address in string format
            for (var i = 0; i < byte_arr.Length; i++)
            {
                if (i % 16 == 0)
                {
                    string ip_addr = getUUID(
                        byte_arr[i], byte_arr[i + 1], byte_arr[i + 2], byte_arr[i + 3],
                        byte_arr[i + 4], byte_arr[i + 5], byte_arr[i + 6], byte_arr[i + 7],
                        byte_arr[i + 8], byte_arr[i + 9], byte_arr[i + 10], byte_arr[i + 11],
                        byte_arr[i + 12], byte_arr[i + 13], byte_arr[i + 14], byte_arr[i + 15]
                        );
                    string_list.Add(ip_addr);
                }
            }
            return string_list;
        }


        static byte[] getBytesFromIPv4(string ipv4_str)
        {
            int ipv4_size = 4;
            byte[] ipv4_bytes = new byte[ipv4_size];
            List<int> Ipv4Vals = ipv4_str.Split('.').Select(int.Parse).ToList();
            for (int i = 0; i < ipv4_size; i++)
            {
                ipv4_bytes[i] = (byte)(Ipv4Vals[i]);
            }
            return ipv4_bytes;
        }


        static byte[] decodeIPv4(List<String> ipv4_str_list)
        {
            int ipv4_size = 4;
            string total_bytes_str = "";
            foreach (string ipv4_str in ipv4_str_list)
            {
                byte[] ipv4_bytes = getBytesFromIPv4(ipv4_str);
                for (int i = 0; i < ipv4_size; i++)
                {
                    total_bytes_str += ipv4_bytes[i].ToString("X2");
                }
            }
            return ToByteArray(total_bytes_str);
        }


        static byte[] decodeIPv6(List<String> ipv6_str_list)
        {
            string total_bytes_str = "";
            foreach (string ipv6_str in ipv6_str_list)
            {
                string ipv6_bytes_str = ipv6_str.Replace(":", "");
                total_bytes_str += ipv6_bytes_str;
            }
            return ToByteArray(total_bytes_str);
        }


        static byte[] decodeMAC(List<String> mac_list)
        {
            string total_bytes_str = "";
            foreach (string mac_str in mac_list)
            {
                string mac_bytes_str = mac_str.Replace("-", "");
                total_bytes_str += mac_bytes_str;
            }
            return ToByteArray(total_bytes_str);
        }


        static string getBytesFromUUID(string ipv4_str)
        {
            string uuid_bytes_str = ipv4_str[6].ToString() + ipv4_str[7].ToString() + ipv4_str[4].ToString() + ipv4_str[5].ToString() + ipv4_str[2].ToString() + ipv4_str[3].ToString() + ipv4_str[0].ToString() + ipv4_str[1].ToString();
            uuid_bytes_str += ipv4_str[11].ToString() + ipv4_str[12].ToString() + ipv4_str[9].ToString() + ipv4_str[10].ToString();
            uuid_bytes_str += ipv4_str[16].ToString() + ipv4_str[17].ToString() + ipv4_str[14].ToString() + ipv4_str[15].ToString();
            uuid_bytes_str += ipv4_str[19].ToString() + ipv4_str[20].ToString() + ipv4_str[21].ToString() + ipv4_str[22].ToString();
            uuid_bytes_str += ipv4_str[24].ToString() + ipv4_str[25].ToString() + ipv4_str[26].ToString() + ipv4_str[27].ToString() + ipv4_str[28].ToString() + ipv4_str[29].ToString() + ipv4_str[30].ToString() + ipv4_str[31].ToString() + ipv4_str[32].ToString() + ipv4_str[33].ToString() + ipv4_str[34].ToString() + ipv4_str[35].ToString();
            return uuid_bytes_str;
        }


        static byte[] decodeUUID(List<String> uuid_list)
        {
            string total_bytes_str = "";
            foreach (string uuid_str in uuid_list)
            {
                string uuid_bytes_str = getBytesFromUUID(uuid_str);
                total_bytes_str += uuid_bytes_str;
            }
            return ToByteArray(total_bytes_str);
        }


        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("[+] SharpObfuscate.exe [OPTION] [PAYLOAD]\n - Options: ipv4, ipv6, mac or uuid.\n - Payload options: Hexadecimal value (starting with 0x or in \\x format), a string, a file path or a URL to download a file.");
                Environment.Exit(0);
            }

            string option = args[0];
            string payload_str = args[1];
            byte[] byte_arr = getPayload(payload_str);
            byte[] decoded_bytes = { };

            List<string> string_list = new List<string>();
            switch (option)
            {
                case "ipv4":
                    string_list = encodeIPv4(byte_arr);
                    decoded_bytes = decodeIPv4(string_list);
                    break;
                case "ipv6":
                    string_list = encodeIPv6(byte_arr);
                    decoded_bytes = decodeIPv6(string_list);
                    break;
                case "mac":
                    string_list = encodeMAC(byte_arr);
                    decoded_bytes = decodeMAC(string_list);
                    break;
                case "uuid":
                    string_list = encodeUUID(byte_arr);
                    decoded_bytes = decodeUUID(string_list);
                    break;
                default:
                    break;
            }

            Console.WriteLine("Number of elements: " + string_list.Count);
            string encoded_result = "\nList<string> string_list = {";
            foreach (string i in string_list)
            {
                encoded_result += ("\"" + i + "\", ");
            }
            encoded_result = encoded_result.Remove(encoded_result.Length - 2, 2);
            encoded_result += "}";
            Console.WriteLine(encoded_result);

            string decoded_result = "\nbyte[] decoded_bytes = {";
            foreach (byte b in decoded_bytes)
            {
                decoded_result += ("0x" + b.ToString("X2") + ", ");
            }
            decoded_result = decoded_result.Remove(decoded_result.Length - 2, 2);
            decoded_result += "}";
            Console.WriteLine(decoded_result);
        }
    }
}