using Firewall.Lists;
using Firewall.Nodes;
using Newtonsoft.Json.Linq;

namespace Firewall
{
    public class Firewall
    {
        private AccessControlList AccessControlList { get; }
        private InterfaceList InterfaceList { get; }
        private FlowNode Flow { get; }

        public Firewall(JObject json, string groupNum)
        {
            var firewall = json;
            var acl = (JArray) firewall.SelectToken("list");
            var interfaceList = (JArray) firewall.SelectToken("interface_id_list");
            var flowNode = (JObject) firewall.SelectToken("flow");
            
            /* To start, we are only working with the BASE ACNode.
               
               TODO: Refactor to allow the use of the ExtendedACNode. */
            AccessControlList = new AccessControlList();
            foreach (var obj in acl)
            {
                var access = (bool)obj["access"];
                var srcIp = (string)obj["src_ip"];
                var srcMask = (string)obj["src_mask"];
                
                AccessControlList.Add(new ACNode("access-list", groupNum, access, srcIp, srcMask));
            }
            
            InterfaceList = new InterfaceList();
            foreach (var obj in interfaceList)
            {
                InterfaceList.Add(new InterfaceNode((string)obj["interface_id"]));
            }
            
            Flow = new FlowNode((string)flowNode["flow_type"], groupNum, (string)flowNode["flow_dir"]);
        }
    }
}