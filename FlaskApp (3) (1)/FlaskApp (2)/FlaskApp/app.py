from flask import Flask, render_template, request, session,redirect, url_for, request
import subprocess
from datetime import datetime
import pandas as pd
import plotly
import plotly.graph_objs as go
#from waitress import serve
import json
import shlex






app = Flask(__name__, static_folder='static')
app.secret_key = 'your_secret_key'



"""
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False) 
    email = db.Column(db.String(120), unique=True, nullable=False) 
    password = db.Column(db.String(120), nullable=False)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password)

    def get_id(self):
        return self.id



@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


"""




@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'hari' or request.form['password'] != '1234':
            error = 'Invalid Credentials. Please try again.'
        else:
            session['logged_in'] = True
            return redirect(url_for('index'))
    return render_template('login.html', error=error)


@app.route('/home') 
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))


    df2 = pd.read_csv('C:\\SecurityLogs.csv')
    data_pie = df2["EventID"].value_counts()
    labels = data_pie.index.tolist()
    values = data_pie.values.tolist()
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hoverinfo='label+percent', textinfo='value',hole=.4,)])
    fig.update_layout(title_text='Security Logs')
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(
    legend=dict(
        font=dict(
            family="Courier New, monospace",
            size=14,
            color="yellow"
        )
    )
    )
    fig.update_layout(paper_bgcolor = "rgba(0,0,0,0)",
                  plot_bgcolor = "rgba(0,0,0,0)")
    total = df2["EventID"].count()
    fig.add_annotation(x= 0.5, y = 0.5,text = f'Total Events: {total}', font = dict(size=10,family='Verdana', color='black'),showarrow = False, )
    chart_dict1 = fig.to_dict()
    chart_json1 = json.dumps(chart_dict1,cls=plotly.utils.PlotlyJSONEncoder)
    


    df3 = pd.read_csv('C:\\ApplicationLogs.csv')
    data_pie = df3["EventID"].value_counts()
    labels = data_pie.index.tolist()
    values = data_pie.values.tolist()
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hoverinfo='label+percent', textinfo='value',hole=.4)])
    fig.update_layout(title_text='Application Logs') 
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(
    legend=dict(
        font=dict(
            family="Courier New, monospace",
            size=14,
            color="yellow"
        )
    )
    )
    fig.update_layout(paper_bgcolor = "rgba(0,0,0,0)",
                  plot_bgcolor = "rgba(0,0,0,0)")
    total = df3["EventID"].count()
    fig.add_annotation(x= 0.5, y = 0.5,text = f'Total Events: {total}', font = dict(size=10,family='Verdana', color='black'),showarrow = False, )
    chart_dict2 = fig.to_dict()
    chart_json2 = json.dumps(chart_dict2)


    df4 = pd.read_csv('C:\\SystemLogs.csv')
    data_pie = df4["EventID"].value_counts()
    labels = data_pie.index.tolist()
    values = data_pie.values.tolist()
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hoverinfo='label+percent', textinfo='value',hole=.5)])
    fig.update_layout(title_text='System Logs')
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(
    legend=dict(
        font=dict(
            family="Courier New, monospace",
            size=14,
            color="yellow"
        )
    )
    )
    fig.update_layout(paper_bgcolor = "rgba(0,0,0,0)",
                  plot_bgcolor = "rgba(0,0,0,0)")
    total = df4["EventID"].count()
    fig.add_annotation(x= 0.5, y = 0.5,text = f'Total Events: {total}', font = dict(size=10,family='Verdana', color='black'),showarrow = False, )
    chart_dict3 = fig.to_dict()
    chart_json3 = json.dumps(chart_dict3)



    return render_template('index.html', chart1=chart_json1, chart2=chart_json2, chart3=chart_json3)





@app.route('/search', methods=['POST','GET'])
def search():
    event_id = request.form['event_id']
    session['event_id'] = event_id
    
    # Escape the event_id to prevent code injection
    safe_event_id = shlex.quote(event_id)
    
    # Execute the PowerShell command and capture the output
    command = f"Get-WinEvent -FilterXPath \"*[System[(EventID='{safe_event_id}')]]\""
    result = subprocess.run(['powershell.exe', '-Command', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

    # Check for errors
    if result.returncode != 0:
        # There was an error, so display the error message
        return render_template("eventid.html", output=result.stderr.strip())
        
    elif result.stdout.strip() == "":
        # The search did not return any results
        return render_template("eventid.html", output="The event ID is not valid.")
        
    else:
        # The search was successful, so redirect to the view_details endpoint
        return redirect(url_for('view_details'))

    

@app.route('/view_details')
def view_details():
    event_id = session.get('event_id')
    if event_id:
        result = subprocess.run(['powershell.exe', f"Get-WinEvent -FilterXPath \"*[System[(EventID='{event_id}')]]\"  -MaxEvents 2| Select-Object TimeCreated, Message, Source, Subject, Id, Level, ComputerName, UserId, TaskCategory, OpCode, RecordId, ProviderName, ProviderId "], stdout=subprocess.PIPE, shell=True)
        if result.stdout:
            output1 = result.stdout.decode('utf-8')
            return render_template("eventid.html", output1=output1)
        else:
            return render_template("eventid.html", output1="No events were found in the System event log.")
    else:
        return redirect(url_for('index'))




@app.route('/alerts', methods=['GET'])
def alerts():


    command = ['powershell.exe', '-Command', 'C:\\Users\\uttha\\OneDrive\\Desktop\\BRUTE.ps1']
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = json.loads(result.stdout.decode('utf-8'))
    alertcount = output['Number of Brute Force Attack Attempts']
    alerts = output['Alerts']
    for alert in output['Alerts']:
        alert['TimeCreated'] = datetime.fromtimestamp(int(alert['TimeCreated'][6:-2])/1000).strftime('%Y-%m-%d %H:%M:%S')
    




  
    command1 = ['powershell.exe','-Command',f'Get-WinEvent -FilterXPath "*[System[(EventID=4758)]]" -erroraction silentlycontinue -MaxEvents 1 |Select-Object TimeCreated, Message, Source, Subject, Id, Level, ComputerName, UserId, TaskCategory, OpCode, RecordId, ProviderName, ProviderId']
    result1= subprocess.run(command1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result1.stdout:
        output1 = result1.stdout.decode('utf-8')
        return render_template("alerts.html", output1=output1)
    else:
        output2="No universal security group was deleted"
        # output2="Misconfigurations in Ports "






    command2 = ['powershell.exe','-Command',f'Get-WinEvent -FilterXPath "*[System[(EventID=4756)]]" -erroraction silentlycontinue -MaxEvents 1 |Select-Object TimeCreated, Message, Source, Subject, Id, Level, ComputerName, UserId, TaskCategory, OpCode, RecordId, ProviderName, ProviderId']
    result2= subprocess.run(command2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result2.stdout:
        output3 = result.stdout.decode('utf-8')
        return render_template("alerts.html", output3=output3)
    else:
        output4="No member was added to a security-enabled universal group"








    # output5="0"
    # output6="0"
    











    return render_template("alerts1.html", alertcount=alertcount, alerts=alerts,output2=output2,output4=output4)

    




    """command = ['powershell.exe', '-Command', 'C:\\Users\\velha\\OneDrive\\Desktop\\rdpalternate.ps1']
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = json.loads(result.stdout.decode('utf-8'))
    alertcount1 = output['Number of Brute Force Attack Attempts']
    alerts1 = output['Alerts']
    for alert in output['Alerts']:
        alert['TimeCreated'] = datetime.fromtimestamp(int(alert['TimeCreated'][6:-2])/1000).strftime('%Y-%m-%d %H:%M:%S')
    return render_template("alerts.html", alertcount=alertcount1, alerts=alerts1)"""










if __name__== '__main__':
    app.run()
    #serve(app, host='0.0.0.0', port=5000) 




















"""
    command1 = ['powershell.exe', '-File', 'C:\\Users\\velha\\OneDrive\\Desktop\\rdpalternate.ps1']
    result1 = subprocess.run(command1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output2 = json.loads(result1.stdout.decode('utf-8'))
    alertcount1 = output2['Number of Remote Desktop and Brute Force Attack Attempts']
    alerts1 = output2['Alerts1']
    for alert in alerts1:
        alert['TimeCreated'] = datetime.fromtimestamp(int(alert['TimeCreated'][6:-2])/1000).strftime('%Y-%m-%d %H:%M:%S')
  """
    
#return render_template("alerts.html", alertcount1=alertcount1, alerts1=alerts1,alertcount=alertcount, alerts=alerts, output3=output3)


"""result2 = subprocess.run(['powershell.exe', f"Get-Eventlog Security -instanceid 4756 -erroraction silentlycontinue"], stdout=subprocess.PIPE, shell=True)
    if result2.stdout:
        output3="No member was added to a security-enabled universal group"
   
    return render_template("alerts.html",alertcount=alertcount, alerts=alerts, output3=output3)"""