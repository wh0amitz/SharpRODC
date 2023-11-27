/*
 Author:     WHOAMI
 Blog:       https://whoamianony.top/
 Twitter:    @wh0amitz
*/
using System;
using System.Collections;
using CommandLine;
using CommandLine.Text;
using SharpRODC.Modules.Objects;

namespace SharpRODC
{
    public class Options
    {

        [Option('d', "Domain", Required = false, HelpText = "Domain (FQDN) to authenticate to.")]
        public string Domain { get; set; }

        [Option('s', "Server", Required = false, HelpText = "IP Address of the domain controller or ldap server.")]
        public string Server { get; set; }

        [Option('u', "Username", Required = false, HelpText = "User to authenticate with.")]
        public string Username { get; set; }

        [Option('p', "Password", Required = false, HelpText = "Password to authenticate with.")]
        public string Password { get; set; }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            var ParserResult = new CommandLine.Parser(with => with.HelpWriter = null)
                .ParseArguments<Options>(args);

            ParserResult
                .WithParsed(options => Run(options))
                .WithNotParsed(errs => DisplayHelp(ParserResult));
        }

        static void DisplayHelp<T>(ParserResult<T> result)
        {
            var helpText = HelpText.AutoBuild(result, h =>
            {
                h.AdditionalNewLineAfterOption = false;
                h.MaximumDisplayWidth = 100;
                h.Heading = "\nSharpRODC 1.0.0-beta"; //change header
                h.Copyright = "Copyright (c) 2023 whoamianony.top"; //change copyright text
                return HelpText.DefaultParsingErrorsHandler(result, h);
            }, e => e);
            Console.WriteLine(helpText);
        }

        private static void Run(Options options)
        {
            string Domain = options.Domain;
            string Server = options.Server;
            string Username = options.Username;
            string Password = options.Password;

            LdapSearch ldapSearch = new LdapSearch(Domain, Server, 389, Username, Password);

            RODC rodc = new RODC(ldapSearch);
            ArrayList RodcLists =  rodc.Run();

            AllowedReplicationGroup allowedReplicationGroup = new AllowedReplicationGroup(ldapSearch);
            allowedReplicationGroup.Run();

            DeniedReplicationGroup deniedReplicationGroup = new DeniedReplicationGroup(ldapSearch);
            deniedReplicationGroup.Run();

            DomainPartition domainPartition = new DomainPartition(ldapSearch, RodcLists);
            domainPartition.Run();
        }
    }
}
