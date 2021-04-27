# Auth0 Application (List Rules for Specific Apps By App)

## Setup and running the application
This application is a .NET v5 app and uses Auth0 for authentication, there is a whitelist of allowed users. The main purpose is to list all rules that target a specific application so these rules are easily visible.

The application also uses authorization and only users assigned the Admin role can visit the page that lists the rules.

To run the application you need to: 
 - Install .NET V5 (This is cross platform) from https://dotnet.microsoft.com/download
 - Clone this repo locally
 - Fire up Terminal on OSX or the command prompt if on Windows
 - Change directory to the root of the project
 - You need to ensure you have a valid SSL certificate for .NET Development. To do this follow the steps below
    - From the project root enter the command 'dotnet dev-certs https --clean'
    - Then enter the command 'dotnet dev-certs https --trust'
 - Type 'dotnet run' also from the project root and you should see output like the below:

 ```
 Building...
info: Microsoft.Hosting.Lifetime[0]
      Now listening on: https://localhost:5001
info: Microsoft.Hosting.Lifetime[0]
      Now listening on: http://localhost:5000
info: Microsoft.Hosting.Lifetime[0]
      Application started. Press Ctrl+C to shut down.
info: Microsoft.Hosting.Lifetime[0]
      Hosting environment: Development
info: Microsoft.Hosting.Lifetime[0]
 ```

Browse to the https location i.e. https://localhost:5001 and this will load the application and it will look like the below:

![Homepage](/images/homepage.png)

## The user accounts
I have create three user accounts for testing:

1.  User: saqib1@yopmail.com
    Password: Welcome.01
    Role: Admin / Whitelisted

2.  User: saqib2@yopmail.com
    Password: Welcome.01
    Role: Standard / Whitelisted

3.  User: saqib3@yopmail.com
    Password: Welcome.01
    Role: This user does not have a role / NOT Whitelisted.

## Testing
**Login to the application as user saqib1@yopmail.com**
I've harnessed some Auth0 functionality to put the username on the nav bar so you can see who has logged in. If you click on it, it will take you to a user profile page with more Auth0 functionality where I've been able to pull some of the claims data and output user specific information like name, email and profile photo, this is all being pulled from Auth0.
Click on the link 'Rules List By App' on the navigation menu. This will take you through to the main page which lists all rules by application, only users with the Admin role in Auth0 can access this page. I used the .NET SDK libraries to get a list of all the rules via the Management API v2. I then use the context.clientName within the script tag on the rule to pull the application name along with the name property to get the rule name and insert those into a dictionary of type (see below) where the application name is the key and the rules for each app are contained within a type of List<string>:

```
Dictionary<string, List<string>> rules_dict =  
                       new Dictionary<string, List<string>>();
```

This then makes it easy to loop through the dicionary items and output the app name along with one or more rules onto the page.

**Logout and then login to the application as saqib2@yopmail.com**
This user account is also whitelisted and has the role of Standard in Auth0 but because they do not have an Admin role assigned they cannot access the 'Rules List By App' page but can access other pages. If you click on it you will get an Access denied message.

**Logout and log back in to the application as saqib3@yopmail.com**
This user account does not have a role and is not whitelisted therefore cannot access the application at all. I have configured the application in the startup.cs class to route non whitelisted users to the logout endpoint if a remote exception is fired i.e. on the Auth0 end via the UnauthorizedError callback in the whitelist rule.
