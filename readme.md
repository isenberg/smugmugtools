# picasaweb2smugmug.py

A tool for copying photos from a Google PicasaWeb account to SmugMug.

The following information is transferred:
* images in full resolution including EXIF tags and original geolocation
* image filename
* image title
* image description text
* order of photos within an album
* album names
* album privacy setting (private, unlisted, public)

The following is lost during the transfer:
* the selection of a album title photo
* modifications to the geolocation which have been added on the Google album

If a folder name is given as option, that folder will be set to unlisted so you can preview the created albums before moving them to the root folder or changing the pricay setting of that new folder.

An option exists to store all photos in a local directory, including the image description as .txt file.

Optionally, an external script can be applied on each image to apply some processing like adding a watermark. See included sample script ```watermark```.

By default it excludes the following automatically created Google+ albums:
* Auto Backups
* Profile Photos
* Photos from Postings. This exclusion is not perfect as it assumes that all albums with just a date as name like 2017-21-01 or 1-21-17 are "photos from postings" albums, which might lead to additional unwanted exclusions, so check the output log.

The code is in part based on the following:
* https://github.com/jackpal/picasawebuploader
* https://github.com/marekrei/smuploader
* http://nathanvangheem.com/news/moving-to-picasa-update

After start, you will be asked to open two URLs in a web browser.
One to allow access to your Picasaweb account
and one to allow access to your SmugMug account.
Only if the --credfile parameter is used, the created API keys are stored on your local system to reuse them on the next start of the tool.

I wrote the tool for migrating my travel photo gallery to http://photos.areo.info of about 1000 photos in 40 albums.

Requires:
* Python 2.7
* some standard python libraries

## Installation on Debian Linux
```
apt-get install python-gdata
apt-get install python-httplib2
pip install google-api-python-client
```

## Installation on MacOS with MacPorts
```
sudo port install py27-pip
sudo -H /opt/local/bin/pip-2.7 uninstall atom 
sudo -H /opt/local/bin/pip-2.7 install gdata google-auth-httplib2 google-api-python-client
sudo -H /opt/local/bin/pip-2.7 install keyring rauth parse
```

## Usage
```
picasaweb2smugmug.py --gmail your.name@gmail.com --smgname smguser \
       --smgfolder import --credfile credentials.json --outdir backupdir
```

Note, that the SmugMug name is the hostname part of the "site URL": https://SMGNAME.smugmug.com

Required Parameters:
 * ```--gmail```  Google email address to access PicasaWeb Archive
 * ```--smgname```  SmugMug user name (site name) to access SmugMug Account

Optional Parameters:
 * ```--smgfolder```  Destination folder where albums should be created
 * ```--credfile```  local storage file, will be created, to reuse authentication on next run
 * ```--outdir```  if given, the Picasaweb photos are copied to this local directory
 * ```--imgcmd```  image processes command to be applied to each photo before uploading
           it is expected to take 2 parameters: input-filename and output-filename
 * ```--imgcmdsfx```  filename suffice to be appended to output-filename, default "_wm"
 * ```--albnr```  only process given album number
 * ```--dry```  dry run, don't write anything to the SmugMug account
