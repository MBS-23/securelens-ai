using System.Data.SqlClient;
using System.Diagnostics;
public class HomeController : Controller {
    [HttpGet("search")]
    public IActionResult Search(string q) {
        var cmd = new SqlCommand("SELECT * FROM Items WHERE Name = '" + q + "'", conn);
        cmd.ExecuteReader();
        return Content(Html.Raw(q).ToString());
    }
    public IActionResult Run(string arg) {
        Process.Start("cmd.exe", "/c " + arg);
        var text = System.IO.File.ReadAllText("/data/" + arg);
        var bf = new BinaryFormatter();
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        var md5 = MD5.Create();
        return Redirect(arg);
    }
}
