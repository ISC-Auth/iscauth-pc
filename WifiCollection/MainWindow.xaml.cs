using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using WebSocketSharp;
using NativeWifi;
using System.Windows.Threading;
using System.Web.Script.Serialization;
using System.Security.Cryptography;
using System.Collections;
using System.Windows.Resources;
using System.Net;
using System.Net.Sockets;

namespace WifiCollection
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        WebSocket ws;
        string api_hostname, identifier, key;
        
        //ArrayList<Dictionary<string, object>>[] wifiInfoArray;
        ArrayList[] wifiInfoArray = new ArrayList[3];
        int nWifiInfoArray = 0;

        DateTime startTime;
        DateTime nowTime;
        int startSeq;
        int nowSeq = 0;

        WlanClient wc = new WlanClient();

        JavaScriptSerializer serializer = new JavaScriptSerializer();

        enum ConnectionState
        {
            noConnection, connectionConfirmed, wifiscanning
        }
        ConnectionState state = ConnectionState.noConnection;

        public MainWindow()
        {
            InitializeComponent();
            //this.Hide();

            ntpOffset = GetNetworkTime() - DateTime.Now;

            for (int i = 0; i < 3; i++)
                wifiInfoArray[i] = new ArrayList();

            icon();
            string[] args = Environment.GetCommandLineArgs();
            try
            {

                printMessage(args[1]);
                setupConnect(args[1]);
            }
            catch (Exception)
            {
                System.Windows.Application.Current.Shutdown();
            }
        }

        TimeSpan ntpOffset;

        DateTime Now()
        {
            return DateTime.Now + ntpOffset;
        }
        

        private void ScanWifiScheduled(DateTime deadline)
        {
            printMessage("Now: " + Now().ToString() + "   Scan at: " + deadline.ToString());
            if ((deadline - Now()).TotalMilliseconds <= 0)
                return;
            System.Timers.Timer timer = new System.Timers.Timer();
            timer.Interval = (deadline - Now()).TotalMilliseconds;
            timer.Elapsed += ScanWifi;
            timer.AutoReset = false;
            timer.Start();
        }

        private void ScanWifi(object sender, System.Timers.ElapsedEventArgs e)
        {
            WlanClient.WlanInterface[] interfaces = wc.Interfaces;
            foreach (WlanClient.WlanInterface wlanInterface in interfaces)
                wlanInterface.Scan();

            System.Timers.Timer timer = new System.Timers.Timer();
            timer.Elapsed += GetWifi;
            timer.Interval = 1000;
            timer.AutoReset = false;
            timer.Start();
        }

        public string ApMac(byte[] macAddr)
        {
            string tMac = "";
            for (int i = 0; i < macAddr.Length; i++)
            {
                tMac += macAddr[i].ToString("x2").PadLeft(2, '0').ToLower();
            }
            return tMac;
        }

        private void GetWifi(object sender, System.Timers.ElapsedEventArgs e)
        {
            wifiInfoArray[nWifiInfoArray].Clear();

            WlanClient.WlanInterface[] interfaces = wc.Interfaces;
            foreach (WlanClient.WlanInterface wlanInterface in interfaces)
            {
                Wlan.WlanBssEntry[] wlanList = wlanInterface.GetNetworkBssList();
                foreach (Wlan.WlanBssEntry wlan in wlanList)
                {
                    Dictionary<string, object> info = new Dictionary<string, object>();
                    info.Add("BSSID", ApMac(wlan.dot11Bssid));
                    info.Add("SSID", System.Text.Encoding.UTF8.GetString(wlan.dot11Ssid.SSID.SubArray(0, (int)wlan.dot11Ssid.SSIDLength)));
                    info.Add("RSSI", wlan.rssi);

                    wifiInfoArray[nWifiInfoArray].Add(info);
                }   
            }

            nWifiInfoArray++;

            nowTime = nowTime.AddSeconds(3);
            ScanWifiScheduled(nowTime);

            if (nWifiInfoArray == 3)
            {
                Dictionary<string, object> data = new Dictionary<string, object>();
                data.Add("action", "WIFIDATA");
                data.Add("source", "pc");
                data.Add("seq", nowSeq);
                data.Add("data", wifiInfoArray);
                string jsonStr = serializer.Serialize(data);
                wsSend(jsonStr);

                nWifiInfoArray = 0;
                nowSeq++;
            }
        }

        private void WebSocketClose(object sender, CloseEventArgs e)
        {
            state = ConnectionState.noConnection;
            printMessage("Disconnected");
        }

        private void WebSocketError(object sender, ErrorEventArgs e)
        {
        }

        private void WebSocketConnect(object sender, EventArgs e)
        {
            printMessage("Connected");
        }

        private void WebSocketMessage(object sender, MessageEventArgs e)
        {
            printMessage("Receive: " + e.Data);

            Dictionary<string, object> JsonData;
            try
            {
                JsonData = serializer.Deserialize<Dictionary<string, object>>(e.Data);
            }
            catch (Exception)
            {
                return;
            }
             
            switch(state)
            {
                case ConnectionState.noConnection:
                    ReplyConnect(JsonData);
                    break;
                case ConnectionState.connectionConfirmed:
                    WifiCollectCheck(JsonData);
                    break;
                case ConnectionState.wifiscanning:
                    break;
            }
                
            
        }

        private void WifiCollectCheck(Dictionary<string, object> JsonData)
        {
            if ((string)JsonData["type"] == "start_wifi_collect")
            {
                DateTime dtStart = TimeZone.CurrentTimeZone.ToLocalTime(new DateTime(1970, 1, 1));
                nowTime = startTime = dtStart.AddSeconds(Convert.ToDouble(JsonData["start_time"]));

                nowSeq = startSeq = (int)JsonData["start_seq"];

                state = ConnectionState.wifiscanning;
                ScanWifiScheduled(nowTime);

                Dictionary<string, object> reply = new Dictionary<string, object>();
                reply.Add("action", "WIFIREPLY");
                reply.Add("source", "pc");
                reply.Add("result", true);
                reply.Add("seq", nowSeq);
                nowSeq++;

                string jsonStr = serializer.Serialize(reply);
                wsSend(jsonStr);
            }
        }

        private void ReplyConnect(Dictionary<string, object> JsonData)
        {
            HMACSHA1 hamc_sha1 = new HMACSHA1(System.Text.Encoding.Default.GetBytes(key));
            byte[] hashbyte = hamc_sha1.ComputeHash(System.Text.Encoding.Default.GetBytes((string)JsonData["random"]));
            string[] byteparts = BitConverter.ToString(hashbyte).Split('-');
            string hashstr = "";
            foreach (string bytepart in byteparts)
            {
                hashstr += bytepart.ToLower();
            }

            Dictionary<string, object> reply = new Dictionary<string, object>();
            reply.Add("action", "ACK");
            reply.Add("random", hashstr);
            string jsonStr = serializer.Serialize(reply);

            wsSend(jsonStr);
            state = ConnectionState.connectionConfirmed;
        }




        private void connect_button_Click(object sender, RoutedEventArgs e)
        {
            setupConnect(url_textbox.Text);
        }

        private void setupConnect(string url)
        {
            url = url.Remove(0, 10);
            string[] str = url.Split('-');

            if (str[2][str[2].Length - 1] == '/')
            {
                str[2] = str[2].Remove(str[2].Length - 1);
            }

            identifier = str[0];
            api_hostname = str[1];
            key = str[2];


            ws = new WebSocket("ws://localhost:8000/api-" + api_hostname + "/" + identifier + "/pc");
            ws.OnMessage += WebSocketMessage;
            ws.OnOpen += WebSocketConnect;
            ws.OnError += WebSocketError;
            ws.OnClose += WebSocketClose;


            ws.Connect();
        }

        private void wsSend(string message)
        {
            printMessage("Send: " + message);
            ws.Send(message);
        }

        private void printMessage(string message)
        {
            this.Dispatcher.Invoke(new Action(delegate
            {
                output.Text += message + "\n";
                output.ScrollToEnd();
            }));
        }

        #region notify
        System.Windows.Forms.NotifyIcon notifyIcon = null;

        private void icon()
        {
            notifyIcon = new System.Windows.Forms.NotifyIcon();
            notifyIcon.BalloonTipText = "Wifi因素认证客户端已开启";

            notifyIcon.Text = "Wifi收集";
            Uri uri = new Uri(@"pack://application:,,,/Resources/WiFi.ico", UriKind.Absolute);
            StreamResourceInfo sri = Application.GetResourceStream(uri);
            notifyIcon.Icon = new System.Drawing.Icon(sri.Stream);
            notifyIcon.Visible = true;

            this.Closed += HideIconWhenClosed;
            
            System.Windows.Forms.MenuItem console = new System.Windows.Forms.MenuItem("Console");
            console.Click += ShowConsole;
            System.Windows.Forms.MenuItem exit = new System.Windows.Forms.MenuItem("Exit");
            exit.Click += CloseApplication;

            System.Windows.Forms.MenuItem[] children = new System.Windows.Forms.MenuItem[] { console, exit };
            notifyIcon.ContextMenu = new System.Windows.Forms.ContextMenu(children);

        }

        private void HideIconWhenClosed(object sender, EventArgs e)
        {
            notifyIcon.Visible = false;
        }   

        private void CloseApplication(object sender, EventArgs e)
        {
            System.Windows.Application.Current.Shutdown();
        }

        private void ShowConsole(object sender, EventArgs e)
        {
            this.Show();
        }
        #endregion

        public static DateTime GetNetworkTime()
        {
            //default Windows time server
            const string ntpServer = "edu.ntp.org.cn";

            // NTP message size - 16 bytes of the digest (RFC 2030)
            var ntpData = new byte[48];

            //Setting the Leap Indicator, Version Number and Mode values
            ntpData[0] = 0x1B; //LI = 0 (no warning), VN = 3 (IPv4 only), Mode = 3 (Client Mode)

            var addresses = Dns.GetHostEntry(ntpServer).AddressList;

            //The UDP port number assigned to NTP is 123
            var ipEndPoint = new IPEndPoint(addresses[0], 123);
            //NTP uses UDP
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            socket.Connect(ipEndPoint);

            //Stops code hang if NTP is blocked
            socket.ReceiveTimeout = 3000;

            socket.Send(ntpData);
            socket.Receive(ntpData);
            socket.Close();

            //Offset to get to the "Transmit Timestamp" field (time at which the reply 
            //departed the server for the client, in 64-bit timestamp format."
            const byte serverReplyTime = 40;

            //Get the seconds part
            ulong intPart = BitConverter.ToUInt32(ntpData, serverReplyTime);

            //Get the seconds fraction
            ulong fractPart = BitConverter.ToUInt32(ntpData, serverReplyTime + 4);

            //Convert From big-endian to little-endian
            intPart = SwapEndianness(intPart);
            fractPart = SwapEndianness(fractPart);

            var milliseconds = (intPart * 1000) + ((fractPart * 1000) / 0x100000000L);

            //**UTC** time
            var networkDateTime = (new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds((long)milliseconds);

            return networkDateTime.ToLocalTime();
        }

        // stackoverflow.com/a/3294698/162671
        static uint SwapEndianness(ulong x)
        {
            return (uint)(((x & 0x000000ff) << 24) +
            ((x & 0x0000ff00) << 8) +
            ((x & 0x00ff0000) >> 8) +
            ((x & 0xff000000) >> 24));
        }
    }
}
