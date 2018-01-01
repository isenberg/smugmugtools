#! /usr/bin/env python2.7
#
# Migrate Picasa Web Album Archive to Smugmug
#
# Requires:
#   Python 2.7
#   gdata 2.0 python library
#
# Holger Isenberg web@areo.info
# 
# based on:
# https://github.com/jackpal/picasawebuploader
# https://github.com/marekrei/smuploader
# http://nathanvangheem.com/news/moving-to-picasa-update
#
# excludes the following automatically created Google+ albums:
# Auto Backups, Photos from Postings, Profile Photos
# https://get.google.com/albumarchive/GOOGLEUSERID/albums/photos-from-posts
# https://get.google.com/albumarchive/GOOGLEUSERID/albums/profile-photos

# Debian Linux:
# apt-get install python-gdata
# apt-get install python-httplib2
# pip install google-api-python-client

# MacOS + MacPorts
# sudo port install py27-pip
# sudo -H /opt/local/bin/pip-2.7 uninstall atom 
# sudo -H /opt/local/bin/pip-2.7 install keyring gdata google-auth-httplib2 google-api-python-client rauth parse

# You will be asked to open two URLs in a web browser.
# One to allow access to your Picasaweb account
# and one to allow access to your SmugMug account.
# Only if the --credfile parameter is used, the created API keys are stored on your local system.

# usage example:
# picasaweb2smugmug.py --gmail your.name@gmail.com --smgname smguser \
#       --smgfolder import --credfile credentials.json --outdir backupdir
# Note, that the smugmuguser is the hostname part of the "site URL": https://SMUGMUGUSER.smugmug.com
#
# Required Parameters:
# --gmail  Google email address to access PicasaWeb Archive
# --smgname  SmugMug user name (site name) to access SmugMug Account
#
# Optional Parameters:
# --smgfolder  Destination folder where albums should be created
# --credfile  local storage file, will be created, to reuse authentication on next run
# --outdir  if given, the Picasaweb photos are copied to this local directory
# --imgcmd  image processes command to be applied to each photo before uploading
#           it is expected to take 2 parameters: input-filename and output-filename
# --imgcmdsfx  filename suffice to be appended to output-filename, default "_wm"
# --albnr  only process given album number
# --dry  dry run, don't write anything to the SmugMug account

import sys
if sys.version_info < (2,7):
    sys.stderr.write("This script requires Python 2.7 or newer.\n")
    sys.stderr.write("Current version: " + sys.version + "\n")
    sys.stderr.flush()
    sys.exit(1)

import argparse
import httplib2, urllib2
import string, unicodedata
import hashlib, re, json
import os, stat, keyring, time, shutil
from rauth import OAuth1Service, OAuth1Session
from urlparse import urlsplit, urlunsplit, parse_qsl
from urllib import urlencode
from datetime import datetime, timedelta
from getpass import getpass
from subprocess import call

# Google Data API and Google OAuth 2
import gdata.photos.service
from oauth2client.contrib.keyring_storage import Storage
from oauth2client.client import OAuth2WebServerFlow

# Google OAuth 2
# App_id, Client_id and Client_secret are permanently registered by the author.
# In case they are removed in the future, create your own OAuth 2 Client entry of type "other"
# on https://console.cloud.google.com/apis and replace them here.
GOOGLE_SCOPE = 'https://picasaweb.google.com/data/'
GOOGLE_REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'
GOOGLE_APP_ID = "picasaweb2smugmug"
GOOGLE_CLIENT_ID = '31124284564-d69979j083npmao9gi5ikpamju7uijs1.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '1ImBw28XFk1qodkDqeOhB60H'

# Smugmug API v2
# APP_name, API_key and API_secret are permanently registered by the author.
# In case they are removed in the future create your own API key of type Application
# on https://api.smugmug.com/api/developer/apply
# and replace them here:
SMG_APP_NAME = "picasaweb2smugmug"
SMG_API_KEY = "vfMbDV2RqXcX8dnFzFtpXvM9vqfnNqmq"
SMG_API_SECRET = "Dw5qfhpjPk8RmPD3jXRmGr69D3LnN4m4fQqVsPxGLjDLJ8RwGS7QN9tH5ZfGpvMs"
SMG_OAUTH_ORIGIN = 'https://secure.smugmug.com'
SMG_REQUEST_TOKEN_URL = SMG_OAUTH_ORIGIN + '/services/oauth/1.0a/getRequestToken'
SMG_ACCESS_TOKEN_URL = SMG_OAUTH_ORIGIN + '/services/oauth/1.0a/getAccessToken'
SMG_AUTHORIZE_URL = SMG_OAUTH_ORIGIN + '/services/oauth/1.0a/authorize'
SMG_API_VERSION = 'v2'
SMG_API_BASE_URL = 'https://api.smugmug.com/api/' + SMG_API_VERSION
SMG_UPLOAD_URI = 'http://upload.smugmug.com/'


def gd_auth(storage):
    gd_client = gdata.photos.service.PhotosService()
    flow = OAuth2WebServerFlow(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_SCOPE, redirect_uri=GOOGLE_REDIRECT_URI)
    authorize_url = flow.step1_get_authorize_url()
    print('\nTo allow read access to your Picasaweb account open the following link in a web browser')
    print('and copy the authentication code shown afterwards:\n\n%s' % authorize_url)
    code = getpass('\nEnter authentication code: ').strip()
    credentials = flow.step2_exchange(code)
    storage.put(credentials)
    return credentials


def gd_login(storage, service_name, user_name):
    try:
        credentials = storage.get()
    except Exception as e:
        print("cannot read Google OAuth credentials from local storage: " + str(e))
        #Probably file could not be found, so redo auth:
        credentials = gd_auth(storage)
    if credentials is None or credentials.invalid:
        #Probably file could not be found, so redo auth:
        credentials = gd_auth(storage)

    credentials = storage.get()
    http = httplib2.Http()
    http = credentials.authorize(http)

    gd_client = gdata.photos.service.PhotosService()
    gd_client.email = user_name
    gd_client.source = service_name
    gd_client.additional_headers = {'Authorization' : 'Bearer %s' % credentials.access_token}

    gd_refresh(gd_client, storage)

    return gd_client


def gd_refresh(gd_client, storage):
    credentials = storage.get()
    http = httplib2.Http()
    if (credentials.token_expiry - datetime.utcnow()) < timedelta(minutes=5):
        credentials.refresh(http)
        gd_client.additional_headers = {'Authorization' : 'Bearer %s' % credentials.access_token}


def smugmug_add_auth_params(auth_url, access=None, permissions=None):
    if access is None and permissions is None:
        return auth_url
    parts = urlsplit(auth_url)
    query = parse_qsl(parts.query, True)
    if access is not None:
        query.append(('Access', access))
    if permissions is not None:
        query.append(('Permissions', permissions))
    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        urlencode(query, True),
        parts.fragment))


def smugmug_get_token(service):
    rt, rts = service.get_request_token(params={'oauth_callback': 'oob'})
    auth_url = smugmug_add_auth_params(service.get_authorize_url(rt), access='Full', permissions='Add')
    print('\nTo allow write access to your Smugmug account')
    print('open the following URL in a web browser and copy the six-digit access code:\n\n%s' % auth_url)
    verifier = getpass('\nEnter the six-digit access code: ').strip()
    at, ats = service.get_access_token(rt, rts, params={'oauth_verifier': verifier})
    return { 'secret': ats, 'token': at }


def smugmug_login(smugmug_credfile):
    service = OAuth1Service(
            name=SMG_APP_NAME,
            consumer_key=SMG_API_KEY,
            consumer_secret=SMG_API_SECRET,
            request_token_url=SMG_REQUEST_TOKEN_URL,
            access_token_url=SMG_ACCESS_TOKEN_URL,
            authorize_url=SMG_AUTHORIZE_URL,
            base_url=SMG_API_BASE_URL)

    if smugmug_credfile:
        try:    
            with open(smugmug_credfile, 'r') as infile:
                smugmugToken = json.load(infile)
        except:
            smugmugToken = smugmug_get_token(service)
            with open(smugmug_credfile, 'w') as outfile:
                os.chmod(smugmug_credfile, stat.S_IRUSR | stat.S_IWUSR)
                json.dump(smugmugToken, outfile)
    else:
        smugmugToken = smugmug_get_token(service)

    session = OAuth1Session(service.consumer_key, service.consumer_secret, access_token=smugmugToken['token'], access_token_secret=smugmugToken['secret'])
    return session


def smugmug_request_once(session, method, url, params={}, headers={}, files={}, data=None, header_auth=False):
    if debug:
        print('\nREQUEST:\nmethod='+method+'\nurl='+url+'\nparams='+str(params) +'\nheaders='+str(headers) + '\nheader_auth='+str(header_auth))
        if len(str(data)) < 300:
            print("data="+str(data))

    response = session.request(url=url,
                    params=params,
                    method=method,
                    headers=headers,
                    files=files,
                    data=data,
                    header_auth=header_auth)

    if debug:
        print('RESPONSE DATA:\n' + str(response.content)[:500] + (" ... " + str(response.content)[-500:] if len(str(response.content)) > 1000 else ""))
    try:
        data = json.loads(response.content)
    except Exception:
        pass
    return data


def smugmug_request(session, method, url, params={}, headers={}, files={}, data=None, header_auth=False, retries=1, sleep=5):
    retry_count=retries
    while retry_count > 0:
        try:
            response = smugmug_request_once(session, method, url, params, headers, files, data, header_auth)
            if ('Code' in response and response['Code'] in [200, 201]) or ("stat" in response and response["stat"] in ["ok"]):
                return response
        except (requests.ConnectionError, requests.HTTPError, requests.URLRequired, requests.TooManyRedirects, requests.RequestException, httplib.IncompleteRead) as e:
            if debug:
                print sys.exc_info()[0]
        if debug:
            print 'Retrying (' + str(retry_count) + ')...'
        time.sleep(sleep)
        retry_count -= 1
    print('Error: Too many retries, giving up.')
    sys.exit(1)


def smugmug_create_nice_name(name):
    return "-".join([re.sub(r'[\W_]+', '', x) for x in name.strip().split()]).title()


def smugmug_get_folders(session, username):
    response = smugmug_request(session, 'GET', SMG_API_BASE_URL + "/folder/user/"+username+"!folders", headers={'Accept': 'application/json'}, header_auth=True)
    folders = []
    if 'Response' in response and 'Folder' in response['Response']:
        for folder in response['Response']['Folder']:
            folders.append({"Name": folder["Name"], "NodeID": folder["NodeID"], "UrlName": folder["UrlName"]})
    return folders


def smugmug_get_folder_id(session, username, folder_name):
    folder_id = None
    for folder in smugmug_get_folders(session, username):
        if folder['Name'] == folder_name:
            folder_id = folder['UrlName']
            break
    return folder_id


def smugmug_create_folder(session, folder_name, username, parent = None, password = None):
    data = {"UrlName": smugmug_create_nice_name(folder_name), "Name": folder_name, "Privacy": "Unlisted"}
    if password != None:
        data['Password'] = password
    response = smugmug_request(session, 'POST', SMG_API_BASE_URL + "/folder/user/" + username + ("/"+parent if parent != None else "") + "!folders", data=json.dumps(data), headers={'Accept': 'application/json', 'Content-Type': 'application/json'}, header_auth=True)
    if debug:
        print json.dumps(response)
    return smugmug_get_folder_id(session, username, folder_name)
    

def smugmug_get_albums(session, username, parent = None):
    response = smugmug_request(session, 'GET', SMG_API_BASE_URL + "/folder/user/" + username + ("/"+parent if parent != None else "") + "!albums", headers={'Accept': 'application/json'}, header_auth=True)
    albums = []
    if 'Response' in response and 'Album' in response['Response']:
        for album in response['Response']['Album']:
            albums.append({"Name": album["Name"], "NiceName": album["NiceName"], "AlbumKey": album["AlbumKey"]})
    return albums


def smugmug_get_album_id(session, username, name, parent = None):
    album_id = None
    for album in smugmug_get_albums(session, username, parent):
        if album['Name'] == name:
            album_id = album['AlbumKey']
            break
    return album_id


def smugmug_create_album(session, username, album_name, password = None, parent = None, template_id = None, privacy = None):
        data = {"NiceName": smugmug_create_nice_name(album_name), "Title": album_name.encode("utf-8"), "Privacy": privacy}
        if password != None:
            data['Password'] = password

        if template_id != None:
            data["AlbumTemplateUri"] = template_id
            data["FolderUri"] = "/api/v2/folder/user/"+username+("/"+parent if parent != None else "")+"!albums"
            response = smugmug_request(session, 'POST', SMG_API_BASE_URL + "/node" + ("/"+parent if parent != None else "")+"!albumfromalbumtemplate", data=json.dumps(data), headers={'Accept': 'application/json', 'Content-Type': 'application/json'}, header_auth=True)
        else:
            response = smugmug_request(session, 'POST', SMG_API_BASE_URL + "/folder/user/" + username + ("/"+parent if parent != None else "") + "!albums", data=json.dumps(data), headers={'Accept': 'application/json', 'Content-Type': 'application/json'}, header_auth=True)

        if debug:
            print json.dumps(response)

        return response


def smugmug_upload_image(session, album_id, local_filename, image_name, image_type, image_title, image_caption):
    with open(local_filename, "rb") as imgfile:
        imgdata = imgfile.read()
        imgfile.close()
        albumURI = "/api/v2/album/" + album_id
        response = smugmug_request(session, 'POST', SMG_UPLOAD_URI,
            data=imgdata,
            header_auth = True,
            headers={'X-Smug-AlbumUri': albumURI, 
                'X-Smug-Version':SMG_API_VERSION, 
                'X-Smug-ResponseType':'JSON',
                'Content-MD5': hashlib.md5(imgdata).hexdigest(),
                'X-Smug-FileName':image_name,
                'Content-Length' : str(len(imgdata)),
                'Content-Type': image_type,
                'X-Smug-Title': image_title,
                'X-Smug-Caption': image_caption})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Migrate photos from PicasaWeb Archive to SmugMug')
    parser.add_argument('--gmail', help='Google account email address', required=True)
    parser.add_argument('--smgname', help='SmugMug username (sitename)', required=True)
    parser.add_argument('--smgfolder', help='SmugMug destination folder name', required=False)
    parser.add_argument('--credfile', help='Permanent credentials storage file', required=False)
    parser.add_argument('--outdir', help='optional output directory for image export', required=False)
    parser.add_argument('--imgcmd', help='optional command applied to each image file', required=False)
    parser.add_argument('--imgcmdsfx', help='filename suffix appended to processed image', required=False)
    parser.add_argument('--albnr', help='limit copy to album number', required=False)
    parser.add_argument('--dry', '-n', help='dry run, don\'t write to SmugMug account', required=False, const=True, nargs='?')
    parser.add_argument('--debug', '-v', help='verbose output for debugging', required=False, const=True, nargs='?')

    args = parser.parse_args()
    debug = args.debug

    tmpdir = "/tmp/picasaweb." + str(os.getpid())
    os.makedirs(tmpdir)

    if args.outdir:
        outdir = args.outdir
        if not os.path.exists(outdir):
            os.makedirs(outdir)
    else:
        outdir = tmpdir
    
    if args.imgcmdsfx:
        imgcmdsfx = args.imgcmdsfx
    else:
        imgcmdsfx = "_wm"

    drynot = "[not] " if args.dry else ""

    gd_storage = Storage(GOOGLE_APP_ID, args.gmail)
    gd_client = gd_login(gd_storage, GOOGLE_APP_ID, args.gmail)
    smg_session = smugmug_login(args.credfile)

    folderID = smugmug_get_folder_id(smg_session, args.smgname, args.smgfolder)
    if not folderID:
        if args.dry:
            print "[not] creating folder: " + args.smgfolder
        else:
            print "creating folder: " + args.smgfolder
            folderID = smugmug_create_folder(smg_session, args.smgfolder, args.smgname, parent=None)
            if not folderID:
                print "ERROR: Failed to create folder. Import to Smugmug canceled."
                sys.exit(1)

    # get list of albums from PicasaWeb
    albums = gd_client.GetUserFeed()
    names = set()
    numAlbumDups = 0
    numPhotos = 0
    numPhotosFailed = 0
    i = 0
    print '\nPicasaweb Albums: '
    for album in albums.entry:
        i += 1
        worktitle = unicode(album.title.text, "utf-8")[0:50]
        # if destination album name already exists, append duplicate counter
        dupn = 0
        albumtitle = worktitle
        while albumtitle in names:
            dupn += 1
            numAlbumDups += 1
            albumtitle = worktitle + " dup " + str(dupn)
        names.add(albumtitle)
            
        # copy access permissions from PicasaWeb
        album_privacy = "Private"
        if album.rights.text == 'protected':
            album_privacy = "Unlisted"
        elif album.rights.text == 'public':
            album_privacy = "Public"
            
        # replace non-ASCII characters in pathname or safe local directory name
        safeChars = "-_.() %s%s" % (string.ascii_letters, string.digits)
        #cleaned_filename = unicodedata.normalize('NFKD', unicode(albumtitle, 'utf8')).encode('ASCII', 'ignore').decode()
        cleaned_filename = unicodedata.normalize('NFKD', albumtitle).encode('ASCII', 'ignore').decode()
        albumdir =  os.path.join(outdir, ''.join(c for c in cleaned_filename if c in safeChars))
        if not os.path.exists(albumdir):
            os.makedirs(albumdir)

        if (args.albnr and not i == int(args.albnr)) \
            or album.title.text == "Auto Backup" \
            or album.title.text == "Profile Photos" \
            or re.match("[0-9]{4}-[0-9]{2}-[0-9]{2}", album.title.text) \
            or re.match("[0-9]{1,2}/[0-9]{1,2}/[0-9]{1,2}", album.title.text) \
            or re.match("[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}", album.title.text):
            print('skipping album %d \"%s\"\n' % (i, album.title.text))
            continue
        else:
            print('album %d \"%s\" %s photos %scopying to \"%s\"' % (i, album.title.text, album.numphotos.text, drynot, albumtitle.encode("utf-8")))

        # Create new SmugMug album. If it already exists, append to it
        albumID = smugmug_get_album_id(smg_session, args.smgname, albumtitle, parent=folderID)
        if not albumID:
            if args.dry:
                print "[not] creating album: " + albumtitle
            else:
                print "creating album: " + albumtitle
                smugmug_create_album(smg_session, args.smgname, albumtitle, parent=folderID, privacy=album_privacy)
                albumID = smugmug_get_album_id(smg_session, args.smgname, albumtitle, parent=folderID)

        # get list of photos in PicasaWeb album
        albumPhotos = gd_client.GetFeed('/data/feed/api/user/%s/albumid/%s?kind=photo&imgmax=d' % (gd_client.email, album.gphoto_id.text))
        numAlbumPhotos = 0
        numPhotoDups = 0
        numPhotosFailed = 0
        filenames = set()
        for photo in albumPhotos.entry:
            numAlbumPhotos += 1
            datePublished = photo.published.text # example: 2016-11-17T06:39:19.000Z
            url = str(photo.content.src)
            urlHandle = urllib2.urlopen(url)
            filename = urllib2.unquote(os.path.basename(urllib2.urlparse.urlparse(urlHandle.url).path))
            if filename in filenames:
                numPhotoDups += 1
                photoidmatch = re.match('.*?([0-9]+)$', photo.id.text)
                photoid = photoidmatch.group(1)
                newfilename = "ID_" + photoid + "_" + filename
            else:
                filenames.add(filename)
                newfilename = filename
            outfilename = os.path.join(albumdir, newfilename)
            if photo.summary.text:
                txtfile = open(outfilename + ".txt", 'w')
                txtfile.write(photo.summary.text)
                txtfile.close()
            if not args.dry:
                imgfile = open(outfilename, 'wb')
                imgfile.write(urlHandle.read())
                imgfile.close()
            if args.imgcmd:
                cmdoutfilenamematch = re.match('.*?/([^/]+?)(\.[a-zA-Z]{0,4}){0,1}$', outfilename)
                cmdoutsuffix = cmdoutfilenamematch.group(2)
                if cmdoutsuffix == None:
                    cmdoutsuffix = ''
                cmdoutfilename = tmpdir + "/" + cmdoutfilenamematch.group(1) + imgcmdsfx + cmdoutsuffix
                if not args.dry:
                    exitcode = call([args.imgcmd, outfilename, cmdoutfilename])
                    if exitcode == 0:
                        if debug:
                            print "command: " + args.imgcmd + " " + outfilename + " " + cmdoutfilename
                        outfilename = cmdoutfilename
                    else:
                        print "command failed: " + args.imgcmd + " " + outfilename + " " + cmdoutfilename
            else:
                cmdoutfilename = None

            # set empty title if only image filename is given here
            if photo.title.text and not re.match("_?(DSC|dsc|IMG|img)[\-_]?[0-9]+", photo.title.text):
                title = photo.title.text.replace("\n", " ")
            else:
                title = None
            if photo.summary.text:
                caption = '<html>' + photo.summary.text.decode('utf-8').encode('ascii', 'xmlcharrefreplace').replace("\n", "<br />") + '</html>'
            else:
                caption = None

            # upload photo to SmugMug
            try:
                if not args.dry:
                    smugmug_upload_image(smg_session, albumID, outfilename, newfilename, "image/jpeg", title, caption)
                print('  photo %d: \"%s\" %scopied' %(numAlbumPhotos, photo.title.text, drynot))
            except Exception:
                numPhotosFailed += 1
                print('  failed to copy photo %d: \"%s\" to \"%s\"' %(numAlbumPhotos, photo.title.text, newfilename))
            
            if cmdoutfilename and os.path.isfile(cmdoutfilename):
                os.remove(cmdoutfilename)

            gd_refresh(gd_client, gd_storage)

        if numPhotoDups > 0:
            print("  duplicate photo filenames (prepended ID to name): " + str(numPhotoDups))
        numPhotos += int(album.numphotos.text)
        print ""

    print("photos copied: " + str(numPhotos))
    print("failed copies: " + str(numPhotosFailed))
    if numAlbumDups > 0:
        print("duplicate album names (appended ID to name): " + str(numAlbumDups))

    if not args.credfile:
        gd_storage.delete()

    # only remove temporary dir, not manually set outdir
    if tmpdir:
        shutil.rmtree(tmpdir)
