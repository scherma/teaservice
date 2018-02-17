using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.Windows.Forms;
using System.Drawing;

namespace TeaService
{
    public class RunInfo
    {
        public string FileName { get; set; }
        public string GetPath { get; set; }
        public int RunStyle { get; set; }
        public string RunUser { get; set; }
        public int RunTimeMs { get; set; }
        public short Year { get; set; }
        public short Month { get; set; }
        public short Day { get; set; }
        public short Hour { get; set; }
        public short Minute { get; set; }
        public short Second { get; set; }
    }

    public class RegistrationInfo
    {
        public string GUID { get; set; }
        public string VMName { get; set; }
        public string OSName { get; set; }
        public string OfficeVersionString { get; set; }
        public string OfficeVersionNum { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public int DisplayHeight { get; set; }
        public int DisplayWidth { get; set; }
    }
    

    class OfficeInfo
    {
        public string version;
        public string vnum;

        public OfficeInfo()
        {
            VersionString();
        }

        private void VersionString()
        {
            RegistryKey key64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            RegistryKey key32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);

            RegistryKey Office32 = key32.OpenSubKey(@"SOFTWARE\Microsoft\Office");
            RegistryKey Office64 = key64.OpenSubKey(@"SOFTWARE\Microsoft\Office");
            
            if (Office32 != null)
            {
                string[] officeKeys = Office32.GetSubKeyNames();
                vnum = Office32.GetSubKeyNames()[0];
                switch (vnum)
                {
                    case "7.0":
                        version = "Microsoft Office 95";
                        break;
                    case "8.0":
                        version = "Microsoft Office 97";
                        break;
                    case "9.0":
                        version = "Microsoft Office 2000";
                        break;
                    case "10.0":
                        version = "Microsoft Office 2002";
                        break;
                    case "11.0":
                        version = "Microsoft Office 2003";
                        break;
                    case "12.0":
                        version = "Microsoft Office 2007";
                        break;
                    case "14.0":
                        version = "Microsoft Office 2010";
                        break;
                    case "15.0":
                        version = "Microsoft Office 2013";
                        break;
                    case "16.0":
                        version = "Microsoft Office 2016";
                        break;
                    default:
                        break;
                }
            }

            if (Office64 != null)
            {
                string[] officeKeys = Office32.GetSubKeyNames();
                vnum = Office32.GetSubKeyNames()[0];
                switch (vnum)
                {
                    case "11.0":
                        version = "Microsoft Office 2003";
                        break;
                    case "12.0":
                        version = "Microsoft Office 2007";
                        break;
                    case "14.0":
                        version = "Microsoft Office 2010";
                        break;
                    case "15.0":
                        version = "Microsoft Office 2013";
                        break;
                    case "16.0":
                        version = "Microsoft Office 2016";
                        break;
                    default:
                        break;
                }
            }
        }
    }

    public class ServiceActions
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEMTIME
        {
            public short Year;
            public short Month;
            public short DayOfWeek;
            public short Day;
            public short Hour;
            public short Minute;
            public short Second;
            public short Millisecond;
        }

        private static HttpClient client = new HttpClient();
        public bool registered = false;
        private string manufacturer = "unsafehex";
        private System.Diagnostics.EventLog eventLog1;

        public string guid;
        public IPAddress gateway;
        public string port = "28080";

        [DllImport("kernel32.dll", EntryPoint = "SetSystemTime", SetLastError = true)]
        public extern static bool Win32SetSystemTime(ref SYSTEMTIME sysTime);

        public ServiceActions()
        {
            //client.Timeout = new TimeSpan(0, 0, 0, 0, 1000);
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            gateway = FindGateway();
            guid = RegValAsString(@"SOFTWARE\Microsoft\Cryptography", "MachineGuid");

            eventLog1 = new System.Diagnostics.EventLog();
            
            eventLog1.Source = "TeaService";
            eventLog1.Log = "TeaSvcLog";

            client.BaseAddress = new Uri($"http://{gateway}:{port}/");
        }

        private IPAddress FindGateway()
        {
            IPAddress addr = NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses)
                .Select(g => g?.Address)
                .Where(a => a != null)
                // .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                // .Where(a => Array.FindIndex(a.GetAddressBytes(), b => b != 0) >= 0)
                .FirstOrDefault();

            return addr;
        }

        public async Task<string> Register(string username, string password, string vmname)
        {
            string responseCode = "";
            if (!UserIsValid(username, password))
            {
                throw new UnauthorizedAccessException("Invalid credentials supplied");
            }
            RegistryKey mfkey = RegKeyFromPath(@"HKEY_LOCAL_MACHINE\SOFTWARE\" + manufacturer, true);
            if (mfkey == null)
            {
                RegistryKey baseKey = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
                mfkey = baseKey.CreateSubKey(manufacturer);
            }

            if (!mfkey.GetValueNames().Contains("Registered"))
            {

                // perform registration
                string uri = "register";

                eventLog1.WriteEntry($"Connecting to registration API at {uri.ToString()}", System.Diagnostics.EventLogEntryType.Information, 104);
                RegistrationInfo ri = new RegistrationInfo();
                OfficeInfo oi = new OfficeInfo();
                ri.GUID = guid;
                ri.VMName = vmname;
                ri.OfficeVersionString = oi.version;
                ri.OfficeVersionNum = oi.vnum;
                ri.username = username;
                ri.password = password;

                // get screen resolution
                ri.DisplayWidth = Screen.PrimaryScreen.Bounds.Width;
                ri.DisplayHeight = Screen.PrimaryScreen.Bounds.Height;

                // get OS version name
                var name = (from x in new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem").Get().Cast<ManagementObject>()
                            select x.GetPropertyValue("Caption")).FirstOrDefault();

                if (name != null)
                {
                    ri.OSName = name.ToString();
                }

                // record successful registration
                HttpResponseMessage registrationResult = await HttpRegistration(uri, ri);

                responseCode = registrationResult.StatusCode.ToString();

                if (registrationResult.IsSuccessStatusCode)
                {
                    mfkey.SetValue("Registered", 1);
                    registered = true;
                    eventLog1.WriteEntry($"Registered with API with status {responseCode}", System.Diagnostics.EventLogEntryType.SuccessAudit, 100);
                }
                else
                {
                    string errstr = registrationResult.ToString();
                    eventLog1.WriteEntry($"Registration failed with error {errstr}", System.Diagnostics.EventLogEntryType.FailureAudit, 105);
                    throw new ApplicationException($"Registration failure with code {errstr}");
                }
                    
            }
            else
            {
                // otherwise registration is complete
                registered = true;
            }

            return responseCode;
        }

        private async Task<HttpResponseMessage> HttpRegistration(string uri, RegistrationInfo info)
        {
            HttpResponseMessage response = await client.PostAsJsonAsync(uri, info);
            return response;
        }

        private RegistryKey RegKeyFromPath(string keyPath)
        {
            RegistryKey output;

            RegistryKey baseKey;
            if (System.Environment.Is64BitOperatingSystem)
            {
                baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            }
            else
            {
                baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            }

            output = baseKey.OpenSubKey(keyPath, RegistryKeyPermissionCheck.ReadSubTree);
            baseKey.Close();
            baseKey.Dispose();
            baseKey = null;

            return output;
        }

        private RegistryKey RegKeyFromPath(string keyPath, bool writeable)
        {
            RegistryKey output;

            RegistryKey baseKey;
            if (System.Environment.Is64BitOperatingSystem)
            {
                baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            }
            else
            {
                baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            }

            output = baseKey.OpenSubKey(keyPath, writeable);
            baseKey.Close();
            baseKey.Dispose();
            baseKey = null;

            return output;
        }

        private string RegValAsString(string keyPath, string valName)
        {
            string result = string.Empty;

            try
            {
                RegistryKey key = RegKeyFromPath(keyPath);
                if (key != null)
                {
                    if (key.GetValueNames().Contains(valName))
                    {
                        result = key.GetValue(valName, (object)"default").ToString();
                    }
                }
                key.Close();
                key.Dispose();
                key = null;
            }
            catch
            {
                // write error log
            }
            return result;
        }

        public async Task<RunInfo> GetRunInfoAsync()
        {
            RunInfo ri = null;
            HttpResponseMessage response = await client.GetAsync($"case/{guid}");
            if (response.IsSuccessStatusCode)
            {
                try
                {
                    ri = await response.Content.ReadAsAsync<RunInfo>();
                }
                catch (Exception ex)
                {
                    eventLog1.WriteEntry($"Error reading job data: {ex.Message}", System.Diagnostics.EventLogEntryType.Error, 211);
                }
            }
            else if (response.StatusCode == HttpStatusCode.NotFound)
            {
                eventLog1.WriteEntry("No work available", System.Diagnostics.EventLogEntryType.Information, 201);
            }
            else
            {
                eventLog1.WriteEntry($"Error {response.StatusCode} getting job", System.Diagnostics.EventLogEntryType.Error, 210);
            }

            return ri;
        }

        public async Task RunAsync()
        {
            RunInfo ri;

            try
            {
                ri = await GetRunInfoAsync();

                if (ri != null)
                {
                    string wdir = $"C:\\Users\\{ri.RunUser}\\Downloads";
                    string filePath = $"{wdir}\\{ri.FileName}";
                    eventLog1.WriteEntry($"Assignment received: {ri.FileName}", System.Diagnostics.EventLogEntryType.Information, 202);

                    using (var response = await client.GetAsync(ri.GetPath))
                    {
                        if (response.IsSuccessStatusCode)
                        {
                            try
                            {
                                var stream = await response.Content.ReadAsStreamAsync();

                                using (var fileStream = File.Create(filePath))
                                {
                                    stream.CopyTo(fileStream);
                                }
                                
                        }
                            catch (Exception ex)
                            {
                                eventLog1.WriteEntry($"Error downloading execution content: {ex.Message}", System.Diagnostics.EventLogEntryType.Error, 213);
                            }
                        }

                        try
                        {
                            SYSTEMTIME st = new SYSTEMTIME();

                            st.Year = ri.Year;
                            st.Month = ri.Month;
                            st.Day = ri.Day;
                            st.Hour = ri.Hour;
                            st.Minute = ri.Minute;
                            st.Second = ri.Second;

                            bool setstatus = Win32SetSystemTime(ref st);

                            if (setstatus)
                            {
                                eventLog1.WriteEntry($"Date and time set", System.Diagnostics.EventLogEntryType.Information, 301);
                                if (ri.RunStyle == 0)
                                {
                                    UserLogins.StartProcessAsUser(ri.RunUser, filePath);
                                }
                                else if (ri.RunStyle == 1)
                                {
                                    UserLogins.StartProcessAsUser(ri.RunUser, "C:\\Windows\\explorer.exe", $"\"{filePath}\"");
                                }
                                else if (ri.RunStyle == 2)
                                {
                                    UserLogins.StartProcessAsUser(ri.RunUser, "C:\\Windows\\System32\\cmd.exe", $"/c start \"{filePath}\"");
                                }

                                eventLog1.WriteEntry($"Successfully started {filePath}", System.Diagnostics.EventLogEntryType.Information, 300);
                                Thread.Sleep(ri.RunTimeMs);
                            }
                            else
                            {
                                eventLog1.WriteEntry($"Failed date/time set", System.Diagnostics.EventLogEntryType.Error, 311);
                            }
                        }
                        catch (Exception ex)
                        {
                            eventLog1.WriteEntry($"Error executing content: {ex.Message}", System.Diagnostics.EventLogEntryType.Error, 310);
                        }
                    }

                }


            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry($"Error obtaining job from server: {ex.Message}", System.Diagnostics.EventLogEntryType.Error, 204);
            }
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
            int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);

        public bool UserIsValid(string userName, string password)
        {
            bool success = false;
            SafeTokenHandle safeTokenHandle;
            try
            {
                string domainName = ".";

                const int LOGON32_PROVIDER_DEFAULT = 0;
                //This parameter causes LogonUser to create a primary token.
                const int LOGON32_LOGON_INTERACTIVE = 2;

                // Call LogonUser to obtain a handle to an access token.
                bool returnValue = LogonUser(userName, domainName, password,
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                    out safeTokenHandle);

                if (false == returnValue)
                {
                    int ret = Marshal.GetLastWin32Error();
                    eventLog1.WriteEntry($"Win32 Error: {ret}", System.Diagnostics.EventLogEntryType.FailureAudit, 103);
                    throw new System.ComponentModel.Win32Exception(ret);
                } else
                {
                    success = true;
                }
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry($"Authentication error: {ex.Message}", System.Diagnostics.EventLogEntryType.FailureAudit, 103);
            }

            return success;
        }

    }

    public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeTokenHandle()
            : base(true)
        {
        }

        [DllImport("kernel32.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }
}
