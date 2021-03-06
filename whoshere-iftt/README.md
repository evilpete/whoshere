# README #

A example program that can me used to trigger Applets via the Maker service webhooks

-------

## whoshere-iftt ##

[whoshere-iftt](/whoshere-iftt/whoshere-iftt.py) is a example program that can me used to trigger [IFTT](https://ifttt.com/) Applets


Sends a web request to notify IFTT of an status change event


### Setup IFTT Applet ###

To set up a IFTT Applet

- On IFTT's "[My Applets](https://ifttt.com/my_applets)" page click "New Applet"

- On IFTT's "[Applets create](https://ifttt.com/create)" page click "New Applet"

    First we set up the trigger using the Maker service webhooks

- Click `+this`

    ![+this](/whoshere-iftt/.screen_shots/Screen_Shot_this.png)

- For `Choose a service` search for `webhooks`

    ![service](/whoshere-iftt/.screen_shots/Screen_Shot_service.png)

- Click on `Webhooks`

- Click `Receive a web request`

- Enter `whoshere` under `Event Name`

    This will be the `IFTT_EVENT` used in [whoshere-iftt](/whoshere-iftt/whoshere-iftt.py)

- Click `Create Trigger`


Next we set up the Action:

- Click "+that"

    ![+that](/whoshere-iftt/.screen_shots/Screen_Shot_that.png)

- Choose action service

    For `Choose action service` pick what you want to happen ( send sms, send a 'tweet', send 'email', etc )


    for a messaged you can include a `ingredient`, where
    `value1` is the target name
    `value2` is the target current valuse
    `value3` is the new value

    for example :

    ![message](/whoshere-iftt/.screen_shots/Screen_Shot_message.png)

- Click `Create action`

- Click `Finish`


##### Get Key ####

Under 'Services'

- Click on `Webhooks`

- Click on `Documentation`


-------

