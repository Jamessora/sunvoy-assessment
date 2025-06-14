# Sunvoy Assessment

Loom link: https://www.loom.com/share/7e021751833c440a9d14bc8b40696225?sid=09a30613-4e2a-423f-b4a8-ebba68878af0

Total time spent: 4 hours

# To setup locally:
Duplicate the env_example and save it as '.env'

Add these

```env
USER_EMAIL=demo@example.org
USER_PASSWORD=test
BASE_URL=https://challenge.sunvoy.com
API_URL=https://api.challenge.sunvoy.com
```

# Executive Summary

You are tasked to reverse engineer a legacy web application that does not have a public API available. We need to programmatically get the list of users and the currently logged in users details.

You can find the legacy application at challenge.sunvoy.com

You can login via demo@example.org and the password “test” and look around freely.

Step 1: GitHub Repository
Create a new public GitHub repository. You will share access to this repository with us when handing in the assignment.

Step 2: Users
Setup a basic node.js script that calls the same internal API challenge.sunvoy.com is using to display users and stores the result in pretty formatted JSON as users.json

Step 3: Currently authenticated user
Afterwards the script should also call the same internal API challenge.sunvoy.com/settings is using to get the currently authenticated users information and add it as an additional item to the same users.json

Step 4: Reuse authentication credentials
Make sure that the script reuses the same authentication credentials if run subsequently and if the credentials are still valid

Step 5: Record a short loom video
Record a short loom video that shows your script in action and add a link to the loom video within a readme.md file

Step 6: Hand in the assignment
Reply to the original email where you received this information and share the link to your public GitHub repository. Please also include the total time you spent on this assignment 

Success criteria:
The script can be executed via npm run start
The script does not throw any errors
The script uses fetch calls to the internal APIs to get the information
Running the script results in a users.json with 10 items
Use the current LTS version of node
You use a minimum of dependencies
