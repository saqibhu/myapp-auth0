using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using myapp_auth0.Models;
using System.Net.Http;
using Newtonsoft.Json.Linq;
using Microsoft.Extensions.Configuration;
using Auth0.ManagementApi;
using Auth0.ManagementApi.Models;
using Auth0.ManagementApi.Paging;


namespace myapp_auth0.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            Configuration = configuration;
        }
        public IConfiguration Configuration { get; }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RulesListByApp()
        {
            var rules = await GetRules();

            Dictionary<string, List<string>> rules_dict =  
                       new Dictionary<string, List<string>>(); 

            foreach(Rule rule in rules)
            {
                string ruleName = rule.Name;
                string ruleScript = rule.Script;

                string appName = getApplicationName(ruleScript);

                //populate dictionary
                if (rules_dict.ContainsKey(appName))
                    rules_dict[appName].Add(ruleName );
                else
                    rules_dict.Add(appName, new List<string> { ruleName });
            }

            ViewData["Rules"] = rules_dict;

            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public async Task<IPagedList<Rule>> GetRules()
        {
            //var CLIENTMANAGEMENTSECRET = Environment.GetEnvironmentVariable("CLIENTMANAGEMENTSECRET");
            var CLIENTMANAGEMENTSECRET = Configuration["Auth0:ClientManagementSecret"];

            using (var client = new HttpClient())
            {
                client.BaseAddress = new System.Uri("https://dev-tslblzvb.eu.auth0.com/");
                var response = await client.PostAsync("oauth/token", new FormUrlEncodedContent(
                    new Dictionary<string, string>
                    {
                                        { "grant_type", "client_credentials" },
                                        { "client_id", "HArPMSSDB2kMPClUwIgPXs6X4QKJ46HE" },
                                        { "client_secret", CLIENTMANAGEMENTSECRET },
                                        { "audience", "https://dev-tslblzvb.eu.auth0.com/api/v2/" }
                    }
                ));
                
                var content = await response.Content.ReadAsStringAsync();
                var jsonResult = JObject.Parse(content);

                //get access token for the management api
                var mgmtToken = jsonResult["access_token"].Value<string>();

                using (var mgmtClient = new ManagementApiClient(mgmtToken, new System.Uri("https://dev-tslblzvb.eu.auth0.com/api/v2")))
                {
                    return await mgmtClient.Rules.GetAllAsync(new GetRulesRequest(), new PaginationInfo());
                }
            }
        }

        private string getApplicationName(string scriptTag)
        {
            if (scriptTag.IndexOf("context.clientName") != -1)
            {
                string mainString = scriptTag.Substring(scriptTag.IndexOf("context.clientName"));
                string start = mainString.Substring(mainString.IndexOf("'")+1);
                int end = start.IndexOf("'");
                return start.Substring(0, end);
            }
            else
            {
                return "Generic Rules";
            }
        }
    }
}
