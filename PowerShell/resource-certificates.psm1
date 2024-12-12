Install-Module -Name OpenSSL
Import-Module -Name OpenSSL

function New-RootCA
{
    [CmdletBinding()]
    Param
    (
            [Parameter(Mandatory=$false, HelpMessage="CA certificate path", ParameterSetName="General")]
            [ValidateNotNullOrEmpty()]
            [string] $RootCAPath,
            [Parameter(Mandatory=$false, HelpMessage = "CA certificate name", ParameterSetName="General")]
            [ValidateNotNullOrEmpty()]
            [string] $RootCAName,
            [Parameter(Mandatory=$false, HelpMessage="Certificate Valid Range", ParameterSetName="General")]
            [ValidateNotNullOrEmpty()]
            [int] $ValidDays = 365,
            [Parameter(Mandatory=$false, HelpMessage="CA Key Password", ParameterSetName="General")]
            [ValidateNotNull()]
            [string]
            $KeyPassword,
            [Parameter(Mandatory=$false, HelpMessage="Overwrite output key file if exists", ParameterSetName="General")]
            [ValidateNotNullOrEmpty()]
            [Switch]
            $Overwrite,
            [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
            [ValidateNotNullOrEmpty()]
            [String]
            $OpenSslPath
    )

    $rootCAKey = "$([System.IO.Path]::Combine($RootCAPath, $rootCAName)).key"
    $rootCACrt = "$([System.IO.Path]::Combine($rootCAPath, $rootCAName)).crt"
    $rootCAExt = "$([System.IO.Path]::Combine($rootCAPath, $rootCAName)).ext"


    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }

    # OpenSSL arguments
    $caArguments = @("req")

    # Algorithm argument
    $caArguments += "-x509"

    $caArguments += "-days"
	$caArguments += "$ValidDays"

    $caArguments += "-newkey"

    $caArguments += "rsa:2048"
        
    # KeyOut argument
    if ($rootCAKey) { 
        if (Test-Path -PathType Container $rootCAKey) { 
            Write-Error "Invalid output key file name"
            Return
        } elseif ((Test-Path -PathType Leaf $rootCAKey) -and (!$Overwrite)) {
            Write-Error "Key file exists (use -Overwrite to overwrite it)"
            Return
        }


        $caArguments += "-keyout"
        $caArguments += "`"$rootCAKey`""
    }

    # Pass and cipher argument
    if ($KeyPassword) {
        #$password = Get-SecurePassword $KeyPassword
        #if (![string]::IsNullOrEmpty($password.Trim())) {
            $caArguments += "-passout"
		    $caArguments += "pass:`"$Keypassword`""
        #}
    }
    
    # Out argument
    if ($rootCACrt) { 
        if (Test-Path -PathType Container $rootCACrt) { 
            Write-Error "Invalid output key file name"
            Return
        } elseif ((Test-Path -PathType Leaf $rootCACrt) -and (!$Overwrite)) {
            Write-Error "Key file exists (use -Overwrite to overwrite it)"
            Return
        }


        $caArguments += "-out"
        $caArguments += "`"$rootCACrt`""
    }

    # Config argument
    if ($rootCAExt) { 
        if (Test-Path -PathType Container $rootCAExt) { 
            Write-Error "Invalid output key file name"
            Return
        } elseif ((Test-Path -PathType Leaf $rootCAExt) -and (!$Overwrite)) {
            Write-Error "Key file exists (use -Overwrite to overwrite it)"
            Return
        }


        $caArguments += "-config"
        $caArguments += "`"$rootCAExt`""
    }

    $caArguments += "-extensions v3_req"
	
	$arguments = [System.String]::Join(" ", $caArguments)

    Execute-OpenSSL -OpenSSLExe $opensslexe -Arguments $arguments

}

function New-CertificateSet
{
    [CmdletBinding()]
    Param
    (
            [Parameter(Mandatory=$false, HelpMessage="CA certificate path", ParameterSetName="General")]
            [ValidateNotNullOrEmpty()]
            [string] $RootCAPath,
            [Parameter(Mandatory=$false, HelpMessage = "CA certificate name", ParameterSetName="General")]
            [ValidateNotNullOrEmpty()]
            [string] $RootCAName,
            [Parameter(Mandatory=$false, HelpMessage = "Certificate Path", ParameterSetName="General")]
            [string] $CertificatePath,
            [Parameter(Mandatory=$false, HelpMessage = "Certificate Name", ParameterSetName="General")]
            [string] $CertificateName,
            [Parameter(Mandatory=$false, HelpMessage = "Certificate Lifespan (days)", ParameterSetName="General")]
            [int] $ValidDays,
            [Parameter(Mandatory=$false, HelpMessage = "Create Key as 3DES", ParameterSetName="General")]
            [switch]
            [bool]
            $3des,
            [Parameter(Mandatory=$false, HelpMessage="CA Key Password", ParameterSetName="General")]
            [ValidateNotNull()]
            [string]
            $KeyPassword,
            [Parameter(Mandatory=$false, HelpMessage="Overwrite output key file if exists", ParameterSetName="General")]
            [ValidateNotNullOrEmpty()]
            [Switch]
            $Overwrite,
            [Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
            [ValidateNotNullOrEmpty()]
            [String]
            $OpenSslPath
    )
    
    $certCrtPath = "$([System.IO.Path]::Combine($certificatePath, $certificateName)).crt"
    $certCsrPath = "$([System.IO.Path]::Combine($certificatePath, $certificateName)).csr"
    $certExtPath = "$([System.IO.Path]::Combine($certificatePath, $certificateName)).ext"
    $certKeyPath = "$([System.IO.Path]::Combine($certificatePath, $certificateName)).key"
    $certPfxPath = "$([System.IO.Path]::Combine($certificatePath, $certificateName)).pfx"
    $certPemPath = "$([System.IO.Path]::Combine($certificatePath, $certificateName)).pem"

    $caCrtPath = "$([System.IO.Path]::Combine($rootCAPath, $rootCAName)).crt"
    $caKeyPath = "$([System.IO.Path]::Combine($rootCAPath, $rootCAName)).key"
    
    # OpenSSL executable
    $opensslexe = "openssl.exe"
    if ($OpenSslPath) {
        if (Test-Path -PathType Container $OpenSslPath) { 
            Write-Error "Invalid openssl file name"
            Return
        }
        if (!(Test-Path -PathType Leaf $OpenSslPath)) {
            Write-Error "Openssl file '$OpenSslPath' not found"
            Return
        }
        $opensslexe = $OpenSslPath
    }
        
    Create-Key -Keypath $certKeyPath -PassIn $KeyPassword -OpenSslExe $opensslexe 
    
    Create-Request  -Keypath $certKeyPath -Csrpath $certCsrPath -Extpath $certExtPath -Name $CertificateName -PassIn $KeyPassword -OpenSslExe $opensslexe
    
    Create-CertificateAsCrt -CaKeyPath $caKeyPath -CaCrtPath $caCrtPath -CsrPath $certCsrPath -CrtPath $certCrtPath -ExtPath $certExtPath -Days $validDays -PassIn $KeyPassword -OpenSslExe $opensslexe
    
    Create-CertficateAsPfx -CaCrtPath $caCrtPath -KeyPath $certKeyPath -CrtPath $certCrtPath -PfxPath $certPfxPath -PassIn $KeyPassword -OpenSslExe $opensslexe
    
    Create-CertificateAsPem -PfxPath $certPfxPath -PemPath $certPemPath -PassIn $KeyPassword -OpenSslExe $opensslexe
}

function Get-SecurePassword
{
    Param(
        [Parameter(Mandatory=$true)]
        [string] $username,
        [Parameter(Mandatory=$false)]
        [string] $password

    )

    if($password)
    {
        $pwd = ConvertTo-SecureString $password -AsPlainText -Force
    }
    else
    {
        $pwd = ConvertTo-SecureString $username -AsPlainText -Force
    }
    
    return $pwd

}

function Execute-OpenSSL
{
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$false, HelpMessage="OpenSSL executable file path", ParameterSetName="General")]
		[ValidateNotNullOrEmpty()]
		[String]
		$OpenSSLExe,
        [Parameter(Mandatory=$false, ParameterSetName="General")]
		[ValidateNotNullOrEmpty()]
		[String]
		$Arguments
	
	)
    # Run command
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$OpenSSLExe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $Arguments
    $pinfo.WorkingDirectory = Convert-Path .
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $pinfo
    $proc.Start() | Out-Null
    $proc.WaitForExit(10000) | Out-Null
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Check errors
    if ($proc.ExitCode) {
        Write-Error $stderr
    } else {
        Write-Output $stdout
    }

    # Verbose output
    Write-Verbose "Output:`n`n$stdout`n`n"
    Write-Verbose "Errors:`n`n$stderr`n`n"

}

function Create-Key
{
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Keypath,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PassIn,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OpenSslExe,
        [Parameter(Mandatory=$false)]
        [Switch]
        $3Des   
        
    )
    $keyArguments = @("genrsa")

    

    #if($3Des)
    #{ 
    #    $keyArguments += "-des3"
    #}

    $keyArguments += "-out"
    $keyArguments += "$KeyPath"
    $keyArguments += "-passout"
    $keyArguments += "pass:`"$PassIn`""
    $keyArguments += "2048"

    $arguments = [System.String]::Join(" ", $keyArguments)

    Execute-OpenSSL -OpenSSLExe $opensslexe -Arguments $arguments
}

function Create-Request
{
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Keypath,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Csrpath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $Extpath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PassIn,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OpenSslExe       
    )
    $csrArguments = @("req")
    
    $csrArguments += "-key"
    $csrArguments += "`"$KeyPath`""

    $csrArguments += "-new"

    $csrArguments += "-out"
    $csrArguments += "`"$CsrPath`""

    $csrArguments += "-config"
    $csrArguments += "`"$ExtPath`""

    $csrArguments += "-extensions"
    $csrArguments += "v3_req"

    $csrArguments += "-subj"
    $csrArguments += "`"/CN=$($Name)`""

    $csrArguments += "-passin"
    $csrArguments += "pass:`"$PassIn`""

    $arguments = [System.String]::Join(" ", $csrArguments)

    Execute-OpenSSL -OpenSSLExe $OpenSslExe -Arguments $arguments
}

function Create-CertificateAsCrt
{
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CaKeyPath,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CaCrtPath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $CsrPath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $CrtPath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $ExtPath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [int]
        $Days,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PassIn,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OpenSslExe       
    )

    $crtArguments = @("x509")

    $crtArguments += "-req"

    $crtArguments += "-CA"
    $crtArguments += "`"$caCrtPath`""

    $crtArguments += "-CAkey"
    $crtArguments += "`"$caKeyPath`""

    $crtArguments += "-in"
    $crtArguments += "`"$CsrPath`""

    $crtArguments += "-out"
    $crtArguments += "`"$CrtPath`""

    $crtArguments += "-days"
    $crtArguments += "$Days"

    $crtArguments += "-CAcreateserial"

    $crtArguments += "-extfile"
    $crtArguments += "`"$ExtPath`""

    $crtArguments += "-extensions v3_req"

    $crtArguments += "-passin"
    $crtArguments += "pass:`"$passIn`""

    $arguments = [System.String]::Join(" ", $crtArguments)

    Write-Verbose $arguments

    Execute-OpenSSL -OpenSSLExe $opensslexe -Arguments $arguments
}

function Create-CertficateAsPfx
{

    Param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CaCrtPath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $PfxPath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $CrtPath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $KeyPath,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PassIn,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OpenSslExe       
    )

    $pfxArguments = @("pkcs12")

    $pfxArguments += "-export"

    $pfxArguments += "-out"
    $pfxArguments += "`"$PfxPath`""

    $pfxArguments += "-in"
    $pfxArguments += "`"$CrtPath`""

    $pfxArguments += "-inkey"
    $pfxArguments += "`"$KeyPath`""

    $pfxArguments += "-certfile"
    $pfxArguments += "`"$CaCrtPath`""

    $pfxArguments += "-passin"
    $pfxArguments += "pass:`"$PassIn`""

    $pfxArguments += "-passout"
    $pfxArguments += "pass:`"$PassIn`""

    $arguments = [System.String]::Join(" ", $pfxArguments)

    Execute-OpenSSL -OpenSSLExe $opensslexe -Arguments $arguments

}

function Create-CertificateAsPem
{
    Param(
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $PfxPath,
        [Parameter(Mandatory=$false)]        
        [ValidateNotNullOrEmpty()]
        [String]
        $PemPath,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PassIn,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OpenSslExe       
    )

    $pemArguments = @("pkcs12")

    $pemArguments += "-info"

    $pemArguments += "-in"
    $pemArguments += "`"$PfxPath`""

    $pemArguments += "-out"
    $pemArguments += "`"$PemPath`""

    $pemArguments += "-nodes"

    $pemArguments += "-passin"
    $pemArguments += "pass:`"$PassIn`""

    
    $arguments = [System.String]::Join(" ", $pemArguments)

    Execute-OpenSSL -OpenSSLExe $opensslexe -Arguments $arguments
}

Export-ModuleMember -Function New-RootCA
Export-ModuleMember -Function New-CertificateSet