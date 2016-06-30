#Период за который подсчитывается количество попыток логина с одного IP (один день)
$mydate=(Get-date).AddDays(-1);

#Узнаем расположение скрипта
$location=$PSScriptRoot;

#Путь до модуля Powershell SQLite. https://github.com/RamblingCookieMonster/PSSQLite
#Этот модуль обеспечивает работу с базой данных SQLite
$PSSQLiteLocation=$Location + "\PSSQLite";

#Подключаем модуль Powershell SQLite.
Import-Module $PSSQLiteLocation;

#Путь до базы данных
$DataSource=$Location + "\adresses.db";

#Имя компьютера
$Hostname = gc env:computername;


$Body=Get-WinEvent -FilterHashtable @{LogName="Security";ID=4625} | Select TimeCreated,@{n="User";e={([xml]$_.ToXml()).Event.EventData.Data | ? {$_.Name -eq "TargetUserName"} | %{$_.'#text'}}},@{n="ComputerName";e={([xml]$_.ToXml()).Event.EventData.Data | ? {$_.Name -eq "WorkstationName"}| %{$_.'#text'}}},@{n="IPAddress";e={([xml]$_.ToXml()).Event.EventData.Data | ? {$_.Name -eq "IPAddress"}| %{$_.'#text'}}} | select-object -first 1
$BodyL = "`n"+$Body.TimeCreated +"`t"+ $Body.User +"`t"+ $Body.ComputerName +"`t"+ $Body.IPAddress

$Insert = "INSERT INTO  FailedLogonEvents (TimeCreated, User, ComputerName, IPAddress, Banned) VALUES (@TimeCreated,@User, @ComputerName,@IPAddress,'0')"


  
 
if(($Body.IPAddress -ne "127.0.0.1") -and ($Body.IPAddress.length -gt 7))
{
    
	Invoke-SqliteQuery -DataSource $DataSource -Query $Insert -SqlParameters @{
        TimeCreated=$Body.TimeCreated
		User=$Body.User
		ComputerName=$Body.ComputerName
		IPAddress=$Body.IPAddress
		
    }
}



$CountIPs="select Count(*) As Attempts from FailedLogonEvents where TimeCreated > @mydate and not Banned = 1 and IPAddress=@IPAddress"


$Attempts = Invoke-SqliteQuery -DataSource $DataSource -Query $CountIPs -SqlParameters @{
        mydate=$mydate
		IPAddress=$Body.IPAddress
    }  



	
	
$Update="UPDATE FailedLogonEvents set Banned='1' where IPAddress=@IPAddress"
If ($Attempts.Attempts -gt 10)
{
	New-NetFirewallRule -Group "AutobanIP" -DisplayName "BlockRemoteIP" -Direction Inbound -RemoteAddress $Body.IPAddress -Action Block
	Invoke-SqliteQuery -DataSource $DataSource -Query $Update -SqlParameters @{
		IPAddress=$Body.IPAddress
    }  
}
