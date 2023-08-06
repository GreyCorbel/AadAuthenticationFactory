public class DeviceCodeHandler
{
    static System.Threading.Tasks.Task _Delegate(Microsoft.Identity.Client.DeviceCodeResult deviceCodeResult)
    {
        System.Console.WriteLine(deviceCodeResult.Message);
        return System.Threading.Tasks.Task.FromResult(0);
    }

    //PS5 has trouble to get correct type when returning static method directly
    public static System.Func<Microsoft.Identity.Client.DeviceCodeResult,System.Threading.Tasks.Task> Get()
    {
        return _Delegate;
    }
}
