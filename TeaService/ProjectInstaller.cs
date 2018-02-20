using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;
using System.Linq;
using System.Threading.Tasks;
using System.ServiceProcess;

namespace TeaService
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : System.Configuration.Install.Installer
    {


        public ProjectInstaller()
        {
            InitializeComponent();
        }

        public override void Install(IDictionary stateSaver)
        {
            base.Install(stateSaver);

            if (System.Diagnostics.EventLog.SourceExists("TeaService"))
            {
                System.Diagnostics.EventLog.DeleteEventSource("TeaService");
            }
            System.Diagnostics.EventLog.CreateEventSource(
                    "TeaService", "TeaSvcLog");

            ServiceActions sc = new ServiceActions();
            
            string httpcode = sc.Register(
                this.Context.Parameters["username"], 
                this.Context.Parameters["password"], 
                this.Context.Parameters["vmname"],
                this.Context.Parameters["malwareX"],
                this.Context.Parameters["malwareY"]).Result;
            if (!sc.registered)
            {
                throw new ApplicationException($"Error {httpcode} registering service");
            }
        }
        
        private void serviceInstaller1_AfterInstall(object sender, InstallEventArgs e)
        {
            using (ServiceController sc = new ServiceController(serviceInstaller1.ServiceName))
            {
                sc.Start();
            }
        }

        private void serviceProcessInstaller1_AfterInstall(object sender, InstallEventArgs e)
        {

        }
    }
}
