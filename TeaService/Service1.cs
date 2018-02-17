using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Net.Http;

namespace TeaService
{
    public partial class Service1 : ServiceBase
    {
        private Timer poll = null;
        private Boolean working = false;
        private ServiceActions actor = new ServiceActions();

        public Service1()
        {
            InitializeComponent();
            eventLog1 = new System.Diagnostics.EventLog();
            if (System.Diagnostics.EventLog.SourceExists("TeaService"))
            {
                System.Diagnostics.EventLog.DeleteEventSource("TeaService");
            }
            System.Diagnostics.EventLog.CreateEventSource(
                    "TeaService", "TeaSvcLog");

            eventLog1.Source = "TeaService";
            eventLog1.Log = "TeaSvcLog";
        }

        protected override void OnStart(string[] args)
        {
            eventLog1.WriteEntry("Checking for jobs", System.Diagnostics.EventLogEntryType.Information, 200);
            poll = new Timer();
            this.poll.Interval = 5000;
            
            this.poll.Elapsed += new System.Timers.ElapsedEventHandler(this.poll_Tick);
            poll.Enabled = true;
        }

        protected override void OnStop()
        {
            poll.Enabled = false;
        }

        private void poll_Tick(object sender, ElapsedEventArgs e)
        {
            if (!working) // no job currently assigned, go get one
            {
                try
                {
                    working = true;
                    actor.RunAsync().Wait();
                    working = false;
                }
                catch (Exception ex)
                {
                    eventLog1.WriteEntry(ex.Message);
                    working = false;
                }
            }
        }

    }
}
