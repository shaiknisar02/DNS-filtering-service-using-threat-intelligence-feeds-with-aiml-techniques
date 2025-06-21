from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from mobileapp.models import Register
from django.contrib import messages
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import RandomOverSampler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score,confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from .models import Register


# Create your views here.
def index(request):
    return render(request,'index.html')

def about(request):
    return render(request,'about.html')

Registration = 'register.html'
def register(request):
    if request.method == 'POST':
        name = request.POST['Name']
        email = request.POST['email']
        password = request.POST['password']
        conpassword = request.POST['conpassword']
        age = request.POST['Age']
        contact = request.POST['contact']
        if password == conpassword:
            user = Register(
                name=name,
                email=email,
                password=password,
                age=age,
                contact=contact
            )
            user.save()
            return render(request, 'login.html')
        else:
            msg = 'Register failed!!'
            return render(request, Registration,{msg:msg})
    return render(request, Registration)

# Login Page 
def login(request):
    if request.method == 'POST':
        lemail = request.POST['email']
        lpassword = request.POST['password']
        d = Register.objects.filter(email=lemail, password=lpassword).exists()
        if d:
            request.session['useremail'] = lemail
            return render(request,'userhome.html',{'email':request.session['useremail']})
        else:
            return render(request, 'login.html')
    return render(request, 'login.html')

def userhome(request):
    return render(request,'userhome.html')

def view(request):
    global df
    if request.method=='POST':
        g = int(request.POST['num'])
        df = pd.read_csv('mobileapp\DNS_kn99.csv')
        col = df.head(g).to_html()
        return render(request,'view.html',{'table':col})
    return render(request,'view.html')

def module(request):
    global df,x_train, x_test, y_train, y_test
    df = pd.read_csv('mobileapp\DNS_kn99.csv')
    # loop through each column in the dataframe
    df.head()
    df= df[['duration','protocol_type','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot','num_failed_logins','logged_in','lnum_compromised','lroot_shell','lnum_file_creations','lnum_shells','label']]
    le=LabelEncoder()
    print(le)
    df['protocol_type']=le.fit_transform(df['protocol_type'])
    df['label']=le.fit_transform(df['label'])
    ##splitting
    x=df.drop('label',axis=1)
    y=df['label']
    x_train,x_test,y_train,y_test = train_test_split(x,y,random_state = 101, test_size = 0.3)
    if request.method=='POST':
        model = request.POST['algo']
        if model == "1":
            from sklearn.neural_network import MLPClassifier
            mlp=MLPClassifier()
            mlp.fit(x_train,y_train)
            re_pred = mlp.predict(x_test)
            ac = accuracy_score(y_test,re_pred)
            ac
            msg='Accuracy of MLPClassifier : ' + str(ac)
            return render(request,'module.html',{'msg':msg})
        elif model == "2":
            from sklearn.tree import DecisionTreeClassifier
            dt = DecisionTreeClassifier()
            dt.fit(x_train, y_train)
            dt_pred = dt.predict(x_test)
            ac1 = accuracy_score(y_test, dt_pred)
            msg = 'Accuracy of DecisionTreeClassifier: ' + str(ac1)
            return render(request, 'module.html', {'msg': msg})
        elif model == "3":
            from sklearn.ensemble import RandomForestClassifier
            rf = RandomForestClassifier()
            rf.fit(x_train, y_train)
            rf_pred = rf.predict(x_test)
            ac2 = accuracy_score(y_test, rf_pred)
            msg = 'Accuracy of RandomForestClassifier: ' + str(ac2)
            return render(request, 'module.html', {'msg': msg})
        elif model == "4":
            from sklearn.naive_bayes import GaussianNB
            nb = GaussianNB()
            nb.fit(x_train, y_train)
            nb_pred = nb.predict(x_test)
            ac3 = accuracy_score(y_test, nb_pred)
            msg = 'Accuracy of GaussianNB: ' + str(ac3)
            return render(request, 'module.html', {'msg': msg})
    return render(request,'module.html')


def prediction(request):
    global df,x_train, x_test, y_train, y_test,df
    if request.method == 'POST':
        f1=float(request.POST['duration'])
        f2=float(request.POST['protocol_type'])
        f5=float(request.POST['src_bytes'])
        f6=float(request.POST['dst_bytes'])
        f7=float(request.POST['land'])
        f8=float(request.POST['wrong_fragment'])
        f9=int(request.POST['urgent'])
        f10=float(request.POST['hot'])
        f11=float(request.POST['num_failed_logins'])
        f12=float(request.POST['logged_in'])
        f13=float(request.POST['lnum_compromised'])
        f14=float(request.POST['lroot_shell'])
        f15=float(request.POST['lnum_file_creations'])
        f16=float(request.POST['lnum_shells'])

        lee=[f1,f2,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16]
        print(lee)

        from sklearn.neural_network import MLPClassifier
        knn = MLPClassifier()
        knn.fit(x_train,y_train)
        result=knn.predict([lee])
        print(result)
        if result==0:
            msg="Attack_type :: back"
        elif result==1:
            msg="Attack_type :: Buffer_overflow"
        elif result==2:
            msg="Attack_type :: Ftp_write"
        elif result==3:
            msg="Attack_type :: Guess_passwd"
        elif result==4:
            msg="Attack_type :: Imap"
        elif result==5:
            msg="Attack_type ::  Ipsweep"
        elif result==6:
            msg="Attack_type ::  Land"
        elif result==7:
            msg="Attack_type ::  Loadmodule"
        elif result==8:
            msg="Attack_type ::  Multihop"
        elif result==9:
            msg="Attack_type ::  Neptune"
        elif result==10:
            msg="Attack_type :: Nmap"
        elif result==11:
            msg="Attack_type ::  Normal"
        elif result==12:
            msg="Attack_type ::  Perl"
        elif result==13:
            msg="Attack_type :: Phf"
        elif result==14:
            msg="Attack_type :: Pod"
        elif result==15:
            msg="Attack_type :: Portsweep"
        elif result==16:
            msg="Attack_type :: Rootkit"
        elif result==17:
            msg="Attack_type :: Satan"
        elif result==18:
            msg="Attack_type :: Smurf"
        elif result==19:
            msg="Attack_type :: Spif"
        elif result==20:
            msg="Attack_type :: Teardrop"
        elif result==21:
            msg="Attack_type :: Warezclient"
        else:
            msg="Attack_type :: Warezmaster"
        return render(request, 'prediction.html', {'msg': msg}) 
    return render(request,'prediction.html')



