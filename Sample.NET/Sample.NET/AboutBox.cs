using System;
using System.Reflection;
using System.Windows.Forms;

using Aladdin.HASP.Envelope;
using Aladdin.HASP.EnvelopeRuntime;


namespace Test_sample {

    partial class AboutBox : Form  {

        public AboutBox() {
            InitializeComponent();

            // Заполняем заголовок и поля About данными из атрибутов сборки
            Text = "About " + AssemblyTitle;
            Sample_Version.Text += AssemblyVersion;
            Sample_Copyright.Text = AssemblyCopyright;
        }

        #region Методы доступа к атрибутам сборки 

        public string AssemblyTitle {
            get {
                var attributes = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyTitleAttribute), false);
                if (attributes.Length > 0) {
                    var titleAttribute = (AssemblyTitleAttribute)attributes[0];
                    if (titleAttribute.Title != "") {
                        return titleAttribute.Title;
                    }
                }
                return System.IO.Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().CodeBase);
            }
        }

        public string AssemblyVersion {
            get {
//                MessageBox.Show("Another instance is already running 1.", "test");
                return Assembly.GetExecutingAssembly().GetName().Version.ToString();
            }
        }

        public string AssemblyMinor {
            get {
                return Assembly.GetExecutingAssembly().GetName().Version.Minor.ToString();
            }
        }

        public string AssemblyGuid {
            get {
                return Assembly.GetExecutingAssembly().GetType().GUID.ToString();
            }
        }

        public string AssemblyDescription {
            get {
                var attributes = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyDescriptionAttribute), false);
                return attributes.Length == 0 ? "" : ((AssemblyDescriptionAttribute)attributes[0]).Description;
            }
        }

        public string AssemblyProduct {
            get {
                var attributes = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyProductAttribute), false);
                return attributes.Length == 0 ? "" : ((AssemblyProductAttribute)attributes[0]).Product;
            }
        }

        public string AssemblyCopyright {
            get {
                var attributes = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyCopyrightAttribute), false);
                return attributes.Length == 0 ? "" : ((AssemblyCopyrightAttribute)attributes[0]).Copyright;
            }
        }

        public string AssemblyCompany {
            get {
                var attributes = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyCompanyAttribute), false);
                return attributes.Length == 0 ? "" : ((AssemblyCompanyAttribute)attributes[0]).Company;
            }
        }
        #endregion

        private void buttonOK_Click(object sender, EventArgs e) {
            Close();
        }
    }
}
