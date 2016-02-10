using CertiPay.Common;
using CertiPay.Common.Logging;
using Nancy.Hosting.Self;
using System;
using System.Configuration;
using Topshelf;

internal class Program
{
    internal static String ServiceName { get { return ConfigurationManager.AppSettings["ApplicationName"]; } }

    internal static String ServiceUri { get; set; }

    private static void Main(string[] args)
    {
        LogManager.Version = Utilities.Version<Program>();

        Program.ServiceUri = ConfigurationManager.AppSettings[ServiceName];

        HostFactory.Run(x =>
        {
            x.Service(() => new WorkerService());

            x.SetDisplayName(ServiceName);
            x.SetServiceName(ServiceName);

            x.AddCommandLineDefinition("ServiceUri", (uri) => Program.ServiceUri = uri);

            x.RunAsLocalSystem();
            x.StartAutomatically();
            x.EnableServiceRecovery(s => s.RestartService(delayInMinutes: 1));
        });
    }

    private class WorkerService : ServiceControl
    {
        private static readonly ILog Log = LogManager.GetLogger<WorkerService>();

        private readonly NancyHost NancyHost;

        public WorkerService()
        {
            this.NancyHost = new NancyHost(new Uri(Program.ServiceUri));
        }

        public bool Start(HostControl hostControl)
        {
            this.NancyHost.Start();
            Log.Info("Starting service, listening at {serviceUri}", Program.ServiceUri);
            return true;
        }

        public bool Stop(HostControl hostControl)
        {
            this.NancyHost.Stop();
            Log.Info("Stopping service");
            return true;
        }

        //public static Uri GetUri(int port = 0)
        //{
        //    port = port == 0 ? FreeTcpPort() : port;

        //    return new Uri("http://localhost:" + port);
        //}

        //private static int FreeTcpPort()
        //{
        //    var listener = new TcpListener(IPAddress.Loopback, 0);

        //    listener.Start();

        //    var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        //    listener.Stop();

        //    return port;
        //}
    }
}