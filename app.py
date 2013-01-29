import os
import urllib2
import httplib2
from tempfile import TemporaryFile

from flask import Flask, render_template, url_for, redirect, request, abort, session, make_response
from werkzeug import secure_filename

from flask.ext.dropbox import Dropbox, DropboxBlueprint

from apiclient.discovery import build_from_document, build
from apiclient.http import MediaFileUpload
from oauth2client.client import OAuth2WebServerFlow

import settings
app = Flask(__name__)

# set up Dropbox
app.config.from_object(settings)
dropbox = Dropbox(app)
dropbox.register_blueprint(url_prefix='/dropbox')

# set up Google API
client_id = settings.GOOGLE_CLIENT_ID
client_secret = settings.GOOGLE_CLIENT_SECRET

@app.route('/login/google')
def login_google():
    flow = OAuth2WebServerFlow(client_id=client_id,
        client_secret=client_secret,
        scope='https://www.googleapis.com/auth/drive.file',
        redirect_uri='http://drizzledrive.herokuapp.com/oauth2callback',
        approval_prompt='force',
        access_type='offline')

    auth_uri = flow.step1_get_authorize_url()
    return redirect(auth_uri)

@app.route('/signout/google')
def signout_google():
    del session['credentials']
    session['message'] = "You have logged out"

    return redirect(url_for('home'))

@app.route('/oauth2callback')
def oauth2callback():
    code = request.args.get('code')
    if code:
        # exchange the authorization code for user credentials
        flow = OAuth2WebServerFlow(settings.GOOGLE_CLIENT_ID,
            settings.GOOGLE_CLIENT_SECRET,
            "https://www.googleapis.com/auth/drive.file")
        flow.redirect_uri = request.base_url
        try:
            credentials = flow.step2_exchange(code)
        except Exception as e:
            print "Unable to get an access token because ", e.message

        # store these credentials for the current user in the session
        session['credentials'] = credentials

    return redirect(url_for('home'))

@app.route('/login/dropbox')
def login_dropbox():
    if not dropbox.is_authenticated:
        return redirect(dropbox.login_url)
    return redirect(url_for('home'))

@app.route('/')
def home():
    if 'credentials' in session:
        logged_in_google = True
    else:
        logged_in_google = False

    if dropbox.is_authenticated:
        logged_in_dropbox = True
    else:
        logged_in_dropbox = False

    return render_template('index.html',
                           logged_in_google=logged_in_google, 
                           logged_in_dropbox=logged_in_dropbox)

# start browsing at the Dropbox root directory
@app.route('/dropbox/')
def dropboxStart():
    if not dropbox.is_authenticated:
        return redirect(dropbox.login_url)

    # set up dropbox
    client = dropbox.client
    folder_metadata = client.metadata('/')

    # if redirected here after an upload
    if request and request.method == 'GET' and request.query_string:
        return render_template('dropbox.html',
                               uploaded=request.args.get('uploaded', None),
                               file_path=folder_metadata['path'],
                               file_data=folder_metadata['contents'])

    return render_template('dropbox.html',
                           file_path=folder_metadata['path'], 
                           file_data=folder_metadata['contents'])

# browse a specific directory in Dropbox
@app.route('/dropbox/<path:folder>')
def dropboxData(folder):
    if not dropbox.is_authenticated:
        return redirect(dropbox.login_url)

    client = dropbox.client
    folder_metadata = client.metadata(folder)
    return render_template('dropbox.html', 
                           file_path=folder_metadata['path'], 
                           file_data=folder_metadata['contents'], 
                           file_root=folder_metadata['root'])

fileInfo = {} # to associate Google Drive file IDs and URLs
@app.route('/edit/<path:filepath>')
def editFile(filepath):
    if not dropbox.is_authenticated:
        return redirect(dropbox.login_url)

    client = dropbox.client

    # downloads from Dropbox
    if filepath[0] != '/': filepath = '/' + filepath # fixes path if broken
    filename = filepath[filepath.rfind('/') + 1:]

    f, metadata = client.get_file_and_metadata(filepath)
    mime_type = metadata['mime_type']
    urlHandler = urllib2.urlopen(client.media(filepath)['url'])
    tf = open(str(filename), 'w+')
    tf.write(urlHandler.read())
    tf.close()
    f.close()

    # uploads to Google Drive
    if 'credentials' not in session:
        session['credentials'] = None
    credentials = session['credentials']
    if credentials == None:
        return redirect(url_for('login_google'))

    http = httplib2.Http()
    http = credentials.authorize(http)
    service = build('drive', 'v2', http=http)
    req = service.files().insert(body={
            'title': filename,
            'mimeType': mime_type,
            'editable': True,
            'description': 'file from Dropbox'
        },
        media_body=MediaFileUpload(tf.name,
                                   mimetype=mime_type,
                                   resumable=True),
        convert=True).execute()
    fileurl = req['alternateLink']
    fileInfo[filepath] = req['id']
    response = make_response(render_template('drive.html',
                           filepath=filepath,
                           filename=filename,
                           fileurl=fileurl))
    response.headers['X-Frame-Options'] = 'GOFORIT'
    return response

@app.route('/upload/<path:filepath>')
def upload(filepath):
    if not dropbox.is_authenticated:
        return redirect(dropbox.login_url)
    client = dropbox.client
    try:
        # checks for Google Drive authorization
        if 'credentials' not in session:
            session['credentials'] = None
        credentials = session['credentials']
        if credentials == None:
            return redirect(url_for('login_google'))

        if filepath[0] != '/': filepath = '/' + filepath # fixes path if broken
        http = httplib2.Http()
        http = credentials.authorize(http)
        service = build('drive', 'v2', http=http)
        req= service.files().get(fileId=fileInfo[str(filepath)]).execute()

        if 'downloadUrl' in req:
            url = req['downloadUrl']
        elif 'webContentLink' in req:
            url = req['webContentLink']
        else: # handle different file types
            if 'document' in req['mimeType']:
                if '.docx' in req['title']:
                    url = req['exportLinks']['application/vnd.openxmlformats-officedocument.wordprocessingml.document']
                elif '.odt' in req['title']:
                    url = req['exportLinks']['application/vnd.oasis.opendocument.text']
                elif '.txt' in req['title'] or '.md' in req['title']:
                    url = req['exportLinks']['text/plain']
                elif '.rtf' in req['title']:
                    url = req['exportLinks']['application/rtf']
                elif '.html' in req['title'] or '.htm' in req['title']:
                    url = req['exportLinks']['text/html']
            elif 'spreadsheet' in req['mimeType']:
                if 'xlsx' in req['title']:
                    url = req['exportLinks']['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']
                elif 'ods' in req['title']:
                    url = req['exportLinks']['application/x-vnd.oasis.opendocument.spreadsheet']
            elif 'presentation' in req['mimeType']:
                url = req['exportLinks']['application/vnd.openxmlformats-officedocument.presentationml.presentation']
            else: # user edited a filetype not supported by Google Drive for export
                url = req['exportLinks']['application/pdf']
                print str(req['title']) + ' converted to PDF'
        
        response, content = http.request(url)
        tf = TemporaryFile()
        tf.write(content)
        tf.seek(0)

        # uploads to dropbox
        client.put_file(filepath, tf, overwrite=True)
        tf.close()
        service.files().delete(fileId=fileInfo.pop(str(filepath))).execute()
        return redirect(url_for('dropboxStart', uploaded='success'))
    except:
        if str(filepath) in fileInfo:
            fileInfo.pop(str(filepath)) # removing the file record
        return redirect(url_for('dropboxStart', uploaded='failed'))

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.debug = True
    app.run(host='0.0.0.0', port=port)