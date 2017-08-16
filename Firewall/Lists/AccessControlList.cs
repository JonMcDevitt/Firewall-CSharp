using System.Collections.Generic;
using System.Linq;
using Firewall.Nodes;

namespace Firewall.Lists
{
    public class AccessControlList
    {
        private List<ACNode> ACL { get; }

        public AccessControlList()
        {
            ACL = new List<ACNode>();
        }

        public void Add(ACNode node)
        {
            ACL.Add(node);
        }

        public void Clear()
        {
            ACL.Clear();
        }

        public int Size()
        {
            return ACL.Count;
        }

        public ACNode Get(int ind)
        {
            return ACL[ind];
        }

        public override string ToString()
        {
            return ACL.Aggregate("", (current, n) => current + (n + "\n"));
        }
    }
}