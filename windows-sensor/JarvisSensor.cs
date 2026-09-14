// Windows-native Event Log collector. No PowerShell, WSL, network, or command execution.
// Compile with the installed .NET Framework compiler; references are framework assemblies.
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace Jarvis.Native {
    public sealed class Sensor : ServiceBase {
        static readonly string[] Channels = {
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-TaskScheduler/Operational"
        };
        readonly string root;
        readonly ManualResetEvent stop = new ManualResetEvent(false);
        Thread worker;
        const long Capacity = 512L * 1024 * 1024;
        static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };

        public Sensor(string directory) { root = directory; ServiceName = "JarvisNativeSensor"; }
        protected override void OnStart(string[] args) {
            worker = new Thread(Run) { IsBackground = true, Name = "jarvis-events" };
            worker.Start();
        }
        protected override void OnStop() { stop.Set(); if(worker != null) worker.Join(15000); }
        static string Hash(string value) {
            using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(value))).Replace("-", "").ToLowerInvariant();
        }
        static void WriteNew(string path, object value) {
            byte[] bytes = new UTF8Encoding(false).GetBytes(Json.Serialize(value));
            if(bytes.Length > 16 * 1024 * 1024) throw new IOException("Batch too large; bookmark retained");
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            using(var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) {
                stream.Write(bytes,0,bytes.Length); stream.Flush(true);
            }
            File.Move(temporary,path); // immutable publication; no overwrite of an existing batch
        }
        static Dictionary<string,object> Read(string path) {
            return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(path));
        }
        void Health(Dictionary<string,object> status) {
            status["schema"]=1; status["time"]=DateTime.UtcNow.ToString("o");
            string path=Path.Combine(root,"health.json");
            string next=path+"."+Guid.NewGuid().ToString("N")+".new";
            WriteNew(next,status);
            if(File.Exists(path)) File.Replace(next,path,null); else File.Move(next,path);
        }
        string Identity() {
            string path=Path.Combine(root,"identity.json");
            if(!File.Exists(path)) WriteNew(path,new Dictionary<string,object> { {"sensor_id",Guid.NewGuid().ToString("D")} });
            return (string)Read(path)["sensor_id"];
        }
        public void Pass() {
            Directory.CreateDirectory(root);
            string sensor=Identity();
            var states=new Dictionary<string,object>();
            foreach(string channel in Channels) {
                if(stop.WaitOne(0)) break;
                try { states[channel]=Collect(sensor,channel); }
                catch(Exception e) { states[channel]=new { status="unavailable", reason=e.GetType().Name+": "+e.Message }; }
            }
            Health(new Dictionary<string,object> { {"sensor_id",sensor}, {"channels",states} });
        }
        object Collect(string sensor,string channel) {
            long used=Directory.EnumerateFiles(root,"*",SearchOption.AllDirectories).Sum(p=>new FileInfo(p).Length);
            if(used >= Capacity) throw new IOException("Spool capacity reached; collection paused without deleting evidence");
            using(var configuration=new EventLogConfiguration(channel)) {
                if(!configuration.IsEnabled) throw new InvalidOperationException("Event channel is disabled");
            }
            string directory=Path.Combine(root,Hash(channel).Substring(0,16));
            Directory.CreateDirectory(directory);
            string latest=Directory.EnumerateFiles(directory,"*.json").OrderByDescending(p=>p,StringComparer.Ordinal).FirstOrDefault();
            long sequence=0;
            string generation=Guid.NewGuid().ToString("D"), bookmark="";
            if(latest != null) {
                var last=Read(latest);
                if((string)last["sensor_id"] != sensor || (string)last["channel"] != channel) throw new InvalidDataException("Spool identity mismatch");
                sequence=Convert.ToInt64(last["sequence"]); generation=(string)last["generation"]; bookmark=(string)last["bookmark"];
            }
            var events=new List<object>();
            string gap=null;
            try { ReadEvents(channel,bookmark,events,ref bookmark); }
            catch(EventLogException e) {
                // A stale bookmark can follow log clearing. Publish a distinct generation
                // and a gap before trying retained history on the next pass.
                // Access/provider failures must not discard a valid bookmark.
                if(e.ErrorCode != 15011 && e.ErrorCode != 15012) throw;
                events.Clear(); bookmark=""; generation=Guid.NewGuid().ToString("D");
                gap="Event Log bookmark invalidated ("+e.ErrorCode+"); retained history will be replayed";
            }
            string status=gap != null || events.Count == 500 ? "partial" : "complete";
            // Empty successful reads still publish bounded cadence health/checkpoints.
            // Throttle heartbeat-only batches to avoid unbounded file churn.
            if(events.Count==0 && gap==null && latest!=null && DateTime.UtcNow-File.GetLastWriteTimeUtc(latest)<TimeSpan.FromMinutes(1))
                return new {status="complete", last_sequence=sequence, observed_at=DateTime.UtcNow.ToString("o")};
            var batch=new Dictionary<string,object> {
                {"schema",1}, {"sensor_id",sensor}, {"host_id",Environment.MachineName},
                {"channel",channel}, {"generation",generation}, {"sequence",sequence+1},
                {"previous_sequence",sequence}, {"created_at",DateTime.UtcNow.ToString("o")},
                {"bookmark",bookmark}, {"status",status}, {"events",events}, {"gap",gap}
            };
            WriteNew(Path.Combine(directory,(sequence+1).ToString("D20")+".json"),batch);
            return new {status=status, last_sequence=sequence+1, events=events.Count, observed_at=DateTime.UtcNow.ToString("o")};
        }
        static void ReadEvents(string channel,string resume,List<object> events,ref string bookmark) {
            var query=new EventLogQuery(channel,PathType.LogName,"*") { ReverseDirection=false, TolerateQueryErrors=false };
            using(var reader=String.IsNullOrEmpty(resume) ? new EventLogReader(query) : new EventLogReader(query,new EventBookmark(resume))) {
                while(events.Count<500) {
                    using(EventRecord record=reader.ReadEvent(TimeSpan.FromSeconds(1))) {
                        if(record==null) break;
                        if(!record.RecordId.HasValue || !record.TimeCreated.HasValue) throw new InvalidDataException("Event identity/time missing");
                        string xml=record.ToXml();
                        if(xml.Length>1024*1024) throw new InvalidDataException("Oversized event; bookmark retained");
                        events.Add(new Dictionary<string,object> {
                            {"record_id",record.RecordId.Value}, {"event_id",record.Id},
                            {"time",record.TimeCreated.Value.ToUniversalTime().ToString("o")}, {"xml",xml}
                        });
                        bookmark=record.Bookmark.BookmarkXml;
                    }
                }
            }
        }
        void Run() {
            // Exclusive process lock protects immutable sequence allocation.
            Directory.CreateDirectory(root);
            using(var gate=new FileStream(Path.Combine(root,"sensor.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)) {
                do {
                    try { Pass(); }
                    catch(Exception e) { try { Health(new Dictionary<string,object>{{"status","unavailable"},{"reason",e.GetType().Name+": "+e.Message}}); } catch {} }
                } while(!stop.WaitOne(2000));
            }
        }
        public static int Main(string[] args) {
            string directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"Jarvis","Sensor");
            if(args.Length==2 && args[0]=="--once") {
                // Explicit path used only for local testing, never supplied to the service.
                using(var sensor=new Sensor(Path.GetFullPath(args[1]))) {
                    Directory.CreateDirectory(sensor.root);
                    using(var gate=new FileStream(Path.Combine(sensor.root,"sensor.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)) sensor.Pass();
                }
                return 0;
            }
            if(args.Length!=0) return 2;
            ServiceBase.Run(new Sensor(directory));
            return 0;
        }
    }
}
