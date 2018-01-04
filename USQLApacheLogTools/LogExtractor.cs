using Microsoft.Analytics.Interfaces;
using Microsoft.Analytics.Types.Sql;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace USQLApacheLogTools
{
    [SqlUserDefinedExtractor]
    public class LogExtractor : IExtractor
    {
        /*
        private string _logType;

        public LogExtractor(string logType)
        {
            this._logType = logType;

        }
        */
        public override IEnumerable<IRow> Extract(IUnstructuredReader input, IUpdatableRow output)
        {
            // This method extracts the apache log in either the NCSA Common Log Format or the Combined log format.
            // Fields are:  remotehost rfc931 authuser [date] method path protocol statusCode bytesSent (referrer) (browser)
            // The last 2 fields are only used in the combined log format.

            string line;
            var reader = new StreamReader(input.BaseStream);
            while ((line = reader.ReadLine()) != null)
            {
                string logPatternSimple = @"^(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] ""(\S+) (\S+)\s*(\S*)"" (\d{3}) (\S+)";
                string logPatternCombined = @"^(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] ""(\S+) (\S+)\s*(\S*)"" (\d{3}) (\S+) ""([^""]+)"" ""([^""]+)""";

                Match matchGroups = Regex.Match(line, logPatternCombined);

                // Check if there is a match using the combined format.  If not, use the simple 
                if (!matchGroups.Success)
                {
                    matchGroups = Regex.Match(line, logPatternSimple);
                }

                int grpCount = matchGroups.Groups.Count;

                // Loop through the groups and set value as a column.
                // Start at group index 1 since index 0 is the entire row.
                // Alternatively, you can specify column names by setting 
                // each column sepcifically: output.Set("remoteHost", matchGroups.Groups[1].Value);
                for (int i = 1; i < grpCount; i++)
                {
                    output.Set(i-1, matchGroups.Groups[i].Value);
                }
                
                yield return output.AsReadOnly();
            }
            yield break;
        }
    }
}