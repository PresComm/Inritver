﻿# Inritver
# v. 0.1 - 11/26/2019
# by PresComm
# https://github.com/PresComm/Inritver
# https://0x00sec.org

#MIT License

<#Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.#>

#Allow user to provide their desired target subnet as a command-line parameter, as well as their desired output format
Param(
    [string]$targets,
    [string]$output,
    [string]$filepath,
    [string]$intarget,
    [string]$help
)
    $global:targets = $targets
    $global:output = $output
    $global:filepath = $filepath
    $global:intarget = $intarget
    $global:help = $help

#Main function
function Execute-Main() {
    Show-Banner

    if ($global:help -eq "True") {
        Show-Help
    }

    Init-Output
    Target-Logic
}

#Banner function
function Show-Banner() {
    #Show banner, version info, authorship, etc.
    cls
    echo "Inritver"
    echo "v. 0.1 - 11/26/2019"
    echo "by PresComm"
    echo "https://github.com/PresComm/Inritver"
    echo "https://0x00sec.org"
    echo ""

    #Trying to poll non-Windows machines results in nasty errors, so let's ignore them and move on when they pop up.
    $global:ErrorActionPreference = 'SilentlyContinue'
}

#Help function
function Show-Help() {
    echo "[===HELP INFORMATION===]"
    echo ""
    echo "When run under the context of a user with admin privileges on the target machines, Inritver will iterate through a user-supplied target or target list and pull BitLocker status for each Windows machine contacted."
    echo ""
    echo "Accepted parameters:"
    echo ""
    echo "-targets"
    echo ""
    echo "Specifies the target(s) to be scanned."
    echo ""
    echo "Examples: 192.168.1.1, 192.168.1.25-50, 192.168.1.0/24"
    echo ""
    echo "-intarget"
    echo ""
    echo "Allows user to specify an input file of targets, one entry per line (see -targets example for acceptable input types.)"
    echo ""
    echo "Example: .\input.txt"
    echo ""
    echo "-output"
    echo ""
    echo "Specifies the output format (if left blank, no file will be output; results will be written to the terminal.)"
    echo ""
    echo "Currently supported output options: TXT, CSV, HTML"
    echo ""
    echo "-filepath"
    echo ""
    echo "Specifies the path for the output file (cannot be used without -output; if left blank, no file will be written [I will address this in an upcoming update])."
    echo ""
    echo "Example: C:\Users\Username\Desktop\Output.txt"
    echo ""
    echo "-help"
    echo ""
    echo "Displays help information."
    echo ""
    echo "Accepted values: true"
    echo ""

    exit
}

#Output init function
function Init-Output(){
    #If an output format of some kind was supplied as a parameter, react accordingly and create the initial file so we can loop through and append to it.
    if ($global:output -eq "TXT"){
        echo "Scan Results" | Select-Object @{Name='Inritver - BitLocker Status Scanner';Expression={$_}} | Out-File $global:filepath
    }
    if ($global:output -eq "CSV"){
        echo "Scan Results" | Select-Object @{Name='Inritver - BitLocker Status Scanner';Expression={$_}} | Export-Csv -Path $global:filepath -NoTypeInformation
    }
    if ($global:output -eq "HTML"){
        echo "Inritver - BitLocker Status Scanner"''"Scan Results" | Select-Object @{Expression={$_}} | ConvertTo-Html | Out-File $global:filepath
    }
}

#Target logic function
function Target-Logic() {
    #Check to see if targets were supplied at the command line. If so, determine what type of target.
    if ($global:targets -ne "") {
        $targetspecified = "Targets"
    }
    #Check to see if an input file for targets was supplied. If so, determine what type of targets.
    if ($global:intarget -ne "") {
        $targetspecified = "Intarget"
    }

    #Check to see if no targets were supplied. If no targets were supplied, throw an error message and exit the script
    if ($targetspecified -ne "Targets" -and $targetspecified -ne "Intarget"){
        echo "Target(s) must be specified either at the command-line or via an input file. For more info run script with -help True."
        echo ""
        exit
    } else {
        #Logic if targets were supplied directly at the command-line.
        if ($targetspecified -eq "Targets") {
            if ($global:targets -like '*-*') {
                Scan-Range
            }
            if ($global:targets -like '*/*') {
                Scan-Subnet
            }
            else {
                if ($global:targets -notlike '*-*' -and $global:targets -notlike '*/*') {
                    Scan-IP
                }
            }
        }
        #Logic if an input file for targets was supplied.
        if ($targetspecified -eq "Intarget") {
            foreach ($line in Get-Content $intarget) {
                if ($line -like '*-*') {
                    $global:targets = $line
                    Scan-Range
                }
                if ($line -like '*/*') {
                    $global:targets = $line
                    Scan-Subnet
                }
                else {
                    if ($line -notlike '*-*' -and $line -notlike '*/*') {
                        $global:targets = $line
                        Scan-IP
                    }
                }
            }
        }
    }
}

#Function for testing connection to current target
function Test-Connection() {
    $requestCallback = $state = $null
    $client = New-Object System.Net.Sockets.TcpClient
    $beginConnect = $client.BeginConnect($global:IP,445,$requestCallback,$state)
    Start-Sleep -milli 3000
    if ($client.Connected) { $global:open = $true } else { $global:open = $false }
    $client.Close()
}

#Function for pulling the BitLocker status from targets and placing it in output files, if specified
function Gather-Status(){
    $FQDN = (Gwmi win32_computersystem –computer $global:IP).DNSHostName+"."+(Gwmi win32_computersystem –computer $global:IP).Domain
				
    echo "Loading results for $global:IP..."
    if ($FQDN -ne $null) {echo "FQDN :: $FQDN"}
    if ($global:output -eq "TXT") {
        echo $global:IP | Select-Object @{Name='Displaying results for...';Expression={$_}}>>$global:filepath
        if ($FQDN -ne $null) {echo "FQDN :: $FQDN">>$global:filepath} 
    }
    if ($global:output -eq "CSV") {
        echo $global:IP | Select-Object @{Name='Displaying results for...';Expression={$_}} | Out-File $global:filepath -Append -Encoding Unicode
        if ($FQDN -ne $null) {echo "FQDN :: $FQDN" | Out-File $global:filepath -Append -Encoding Unicode}
    }
    if ($global:output -eq "HTML") {
        echo "Displaying results for"''$global:IP | Select-Object @{Expression={$_}} | ConvertTo-Html | Out-File $global:filepath -Append -Encoding Unicode
        if ($FQDN -ne $null) {echo "FQDN :: $FQDN" | Out-File $global:filepath -Append -Encoding Unicode}
    }

    #This is the function that actually polls each target for BitLocker status.
    $global:blstatus = manage-bde -status c: -ComputerName $global:IP
    $global:blstatus = Write-Output $global:blstatus | findstr /i "Status"

    if ($global:output -eq "TXT") {
        $global:blstatus>>$global:filepath
    }
    if ($global:output -eq "CSV") {
        echo $global:blstatus | Out-File $global:filepath -Append -Encoding Unicode
    }
    if ($global:output -eq "HTML") {
        echo $global:blstatus | Out-File $global:filepath -Append -Encoding Unicode
    }
    else {
        $global:blstatus |% { 
            $_.partcomponent –match “.+Domain\=(.+)\,Name\=(.+)$” > $nul 
            $matches[1].trim('"') + “\” + $matches[2].trim('"') 
		}
	}	

	echo ""
}

#Function for scanning single IPs
function Scan-IP(){
    echo "Beginning scan of $global:targets..."
    echo ""

    $global:IP = $global:targets

    Test-Connection

    if ($global:open -eq "True") {

        Gather-Status

    }
}

#Function for scanning address ranges
function Scan-Range(){
    echo "Beginning scan of $global:targets..."
    echo ""
    
    $firstset = $global:targets
    $secondset = $global:targets

    $root = $firstset.split('-')[0]
    $lastipoct = $secondset.split('-')[-1]
    $firstipoct = $root.split('.')[-1]

    $root = $root -split '\.' | ForEach-Object {
        [System.Convert]::ToString($_,2).PadLeft(8,'0')
    }

    $root = $root -join ''

    $firstoctet = $root.SubString(0,8)
    $thirdoctet = $root.SubString(16,8)
    $secondoctet = $root.SubString(8,8)

    $firstoctet = $firstoctet | ForEach-Object {
        [System.Convert]::ToByte($_,2)
    }
    $secondoctet = $secondoctet | ForEach-Object {
        [System.Convert]::ToByte($_,2)
    }
    $thirdoctet = $thirdoctet | ForEach-Object {
        [System.Convert]::ToByte($_,2)
    }

    $root = "$firstoctet"+'.'+"$secondoctet"+'.'+"$thirdoctet"

    $totaltargets = $lastipoct - $firstipoct

    $currentoct = $firstipoct

    do {
        $global:IP = "$root"+'.'+"$currentoct"
        
        Test-Connection

        if ($global:open -eq "True") {

            Gather-Status
           
        }
            $totaltargets = $totaltargets - 1
            [int]$currentoct = [int]$currentoct + 1
        
    } while ($totaltargets -gt -1)
}

#Function for scanning subnets
function Scan-Subnet(){
    echo "Beginning scan of $global:targets..."
    echo ""
    #This is the function that iterates through the user-supplied subnet.
    #Credit for this portion of the script goes to Mark Gossa
    #on the Microsoft TechNet Gallery (https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Subnet-db45ec74).
    #I ensured the license is fine for me to include this function in my script.
    foreach ($subnet in $global:targets) {
        
        #Split IP and subnet
        $global:IP = ($Subnet -split "\/")[0]
        $SubnetBits = ($Subnet -split "\/")[1]
        
        #Convert IP into binary
        #Split IP into different octects and for each one, figure out the binary with leading zeros and add to the total
        $Octets = $global:IP -split "\."
        $IPInBinary = @()

        foreach($Octet in $Octets) {
            #convert to binary
            $OctetInBinary = [convert]::ToString($Octet,2)
                
            #get length of binary string add leading zeros to make octet
            $OctetInBinary = ("0" * (8 - ($OctetInBinary).Length) + $OctetInBinary)

            $IPInBinary = $IPInBinary + $OctetInBinary
        }

        $IPInBinary = $IPInBinary -join ""

        #Get network ID by subtracting subnet mask
        $HostBits = 32-$SubnetBits
        $NetworkIDInBinary = $IPInBinary.Substring(0,$SubnetBits)
        
        #Get host ID and get the first host ID by converting all 1s into 0s
        $HostIDInBinary = $IPInBinary.Substring($SubnetBits,$HostBits)        
        $HostIDInBinary = $HostIDInBinary -replace "1","0"

        #Work out all the host IDs in that subnet by cycling through $i from 1 up to max $HostIDInBinary (i.e. 1s stringed up to $HostBits)
        #Work out max $HostIDInBinary
        $imax = [convert]::ToInt32(("1" * $HostBits),2) -1

        $IPs = @()

        #Next ID is first network ID converted to decimal plus $i then converted to binary
        For ($i = 1 ; $i -le $imax ; $i++) {
            #Convert to decimal and add $i
            $NextHostIDInDecimal = ([convert]::ToInt32($HostIDInBinary,2) + $i)
            #Convert back to binary
            $NextHostIDInBinary = [convert]::ToString($NextHostIDInDecimal,2)
            #Add leading zeros
            #Number of zeros to add 
            $NoOfZerosToAdd = $HostIDInBinary.Length - $NextHostIDInBinary.Length
            $NextHostIDInBinary = ("0" * $NoOfZerosToAdd) + $NextHostIDInBinary

            #Work out next IP
            #Add networkID to hostID
            $NextIPInBinary = $NetworkIDInBinary + $NextHostIDInBinary
            #Split into octets and separate by . then join
            $global:IP = @()

            For ($x = 1 ; $x -le 4 ; $x++) {
                #Work out start character position
                $StartCharNumber = ($x-1)*8
                #Get octet in binary
                $IPOctetInBinary = $NextIPInBinary.Substring($StartCharNumber,8)
                #Convert octet into decimal
                $IPOctetInDecimal = [convert]::ToInt32($IPOctetInBinary,2)
                #Add octet to IP 
                $global:IP += $IPOctetInDecimal
            }

            #Separate by .
            $global:IP = $global:IP -join "."
            $FQDN = $null

            Test-Connection

            if ($global:open -eq "True") {

                Gather-Status
                
			}
        }
    }
}

Execute-Main