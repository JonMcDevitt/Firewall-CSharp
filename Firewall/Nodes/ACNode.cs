using System;
using System.Collections.Generic;
using System.Linq;

namespace Firewall.Nodes
{
    public class ACNode
    {
        internal string AccessList { get; set; } /* Stores the 'access-list' directive. Candidate for removal. */
        internal string GroupNumber { get; set; } /* Stores the access group ths node belongs to. */

        internal bool Access { get; set; } /* Stores the access permissions for packets with the following source IP
                                                and mask.*/

        internal string SrcIp { get; set; } /* Stores the packet's source IP. */
        internal string SrcMask { get; set; } /* Stores the packet's source mask. */

        public ACNode(string accessList, string groupNum, bool access, string srcIp, string srcMask)
        {
            AccessList = accessList;
            GroupNumber = groupNum;
            Access = access;
            SrcIp = srcIp;
            SrcMask = srcMask;
        }

        /// <summary>
        /// CheckSource(ip)
        /// 
        /// Client-facing function. Given an IP address, check that it is compatible with this ACNode's source and mask.
        /// 
        /// </summary>
        /// <param name="ip"></param>
        /// <returns></returns>
        public bool CheckSource(string ip)
        {
            return CheckSource(ip, null, null);
        }
        
        /// <summary>
        /// CheckSource(ip, src, mask)
        /// 
        /// Given an IP address, check that it is compatible with a given source IP and its corresponding IP mask.
        /// 
        /// Algorithm
        ///     1. Find the bit strings associated with the IP address. Split into the following sub-steps:
        ///         A. Convert the "xxx.yyy.zzz.www" string into an array of strings representing each part of the IP
        ///            address. I.e:
        ///                 "xxx.yyy.zzz.www" --> {"xxx", "yyy", "zzz", "www"}
        ///         B. For each string in the array from A, convert to a string array representing their bits:
        ///                 {"xxx", "yyy", "zzz", "www"} --> { "aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd" }
        ///            where a, b, c, and d have a corresponding bit value of 0 or 1
        ///         C. For each string in the array from B, convert to a two-dimensional array of characters which hold
        ///            the appropriate bits at each index. Not strictly necessary, but char arrays are preferable to
        ///            work with compared to string arrays.
        ///     2. Using the src/dest IP + Mask, create a 'working' mask. The working mask identifies which bits are
        ///        significant (i.e. which ones we care about) and transfers them over exactly, while insignificant bits
        ///        (marked as a '1' in the mask) are marked with an 'i' for "I don't care".
        ///     3. Using the working mask, establish whether the given IP address is valid based on the src/dest IP +
        ///        mask.
        ///         
        /// </summary>
        /// <param name="ip">The IP address to compare.</param>
        /// <param name="src">The IP address to compare against. Required for CheckDest call.</param>
        /// <param name="mask">The mask of the IP address to compare against. Required for CheckDest call.</param>
        /// <returns>boolean - Whether or not the IP and Src+Mask are compatible.</returns>
        internal bool CheckSource(string ip, string src, string mask)
        {
            if (!Access)
            {
                return false;
            }
            
            if (src == null)
            {
                src = SrcIp;
            }

            if (mask == null)
            {
                mask = SrcMask;
            }

            /* 1. Find bit strings. */
            string[] baseIP = ip.Split('.'), baseSource = src.Split('.'), baseMask = mask.Split('.');

            var ipAsBytes = ConvertToByteString(baseIP);
            var srcAsBytes = ConvertToByteString(baseSource);
            var maskAsBytes = ConvertToByteString(baseMask);

            char[][] ipIn = ConvertIpStringToIpChars(ipAsBytes),
                srcIn = ConvertIpStringToIpChars(srcAsBytes),
                maskIn = ConvertIpStringToIpChars(maskAsBytes);

            /* 2. Create working mask. */
            var workingMask = GetWorkingMask(srcIn, maskIn);

            /* 3. Check for a match. */
            return Matches(ipIn, workingMask);
        }

        private static IEnumerable<string> ConvertToByteString(IEnumerable<string> ip)
        {
            return ip.Select(bit => Convert.ToString(int.Parse(bit), 2).PadLeft(8, '0')).ToArray();
        }
        
        /* TODO - Correct program to also get the byte pattern (i.e. 1s and 0s) for the source and mask */
        
        private static char[][] ConvertIpStringToIpChars(IEnumerable<string> ip)
        {
            return ip.Select(bit => bit.ToCharArray()).ToArray();
        }

        private static char[][] GetWorkingMask(IReadOnlyList<char[]> source, IReadOnlyList<char[]> mask)
        {
            var workingMask = new char[4][];
            for (var i = 0; i < workingMask.Length; i++)
            {
                workingMask[i] = new char[8];
            }

            for (var i = 0; i < workingMask.Length; i++)
            {
                for (var j = 0; j < workingMask[i].Length; j++)
                {
                    if (mask[i][j] == '0')
                    {
                        workingMask[i][j] = source[i][j];
                    }
                    else
                    {
                        workingMask[i][j] = 'i';
                    }
                }
            }

            return workingMask;
        }

        private static bool Matches(IReadOnlyList<char[]> ipIn, IReadOnlyList<char[]> workingMask)
        {
            for (var i = 0; i < ipIn.Count; i++)
            {
                for (var j = 0; j < ipIn[i].Length; j++)
                {
                    if (workingMask[i][j] != 'i' &&
                        workingMask[i][j] != ipIn[i][j])
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        public override string ToString()
        {
            var msg = "";

            msg += AccessList + "\t";
            msg += GroupNumber + "\t";
            msg += (Access ? "permit" : "deny") + "\t";
            msg += SrcIp + "\t";
            msg += SrcMask + "\n";

            return msg;
        }
    }
}