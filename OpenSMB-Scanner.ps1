
$date = get-date -f "dd-MM"
$GLOBAL:logPath = "$PSScriptRoot\report-$date.csv"

function get-Servers() {
    $servers = Get-ADComputer -Filter {
        (OperatingSystem -Like "* 2003") -or 
        (OperatingSystem -Like "* 2008 Standard*") -or
        (OperatingSystem -Like "* 2008 R2 *") -or 
        (OperatingSystem -Like "* 2012 *")
    }
    $list = @()
    $size = 0
    foreach($server in $servers) {
        if(($server.enabled -eq $true) -and
          (-not($server.DistinguishedName -Like "*Domain Controllers*"))) {
            $list += $server.name
            $size++
        }
    }
    return $list
}

function log {
    param([String]$text) 
    
    add-content $GLOBAL:logPath $text
    write-host "[CONSOLE] $text" -f gray
}

if(test-path($GLOBAL:logPath)) {
    Remove-Item $GLOBAL:logPath
}

add-content $GLOBAL:logPath "Servidor;Compartilhamento;Objeto;Permissão;Tipo"

$servers = get-Servers
$max = $servers.count
$count = 1

foreach($server in $servers) {

    write-progress -activity "SHARE-SCAN" -status "Progresso: $count-$max servidores" -percentcomplete ($count/($max)*100)

    $shares = Get-WmiObject -Class Win32_Share -ComputerName $server -Property * 
    $ignore = @("C$","D$","E$","ADMIN$","IPC$")
    $locations = @()

    foreach($share in $shares) {
    
        $name = $share.name
        $allow = $true
        foreach($rule in $ignore) {
            if($share.name -eq $rule) {
                    $allow = $false
            }
        }
        if($allow) {
            try {
                if(test-path("\\$server\$name")) {
                    $locations += "\\$server\$name"
                } else {
                    write-host "[INFO] ($server) cannot access $name" -f red
                }
            } catch [system.ItemExistsUnauthorizedAccessError] { }
        }
    
    }

    foreach($location in $locations) {

        $ShareName = $location.split("\")[3]

        #NTFS
        $acl = Get-Acl $location
        foreach($accessRule in $acl.Access) {
           $object = $accessRule.IdentityReference
           $permission = $accessRule.FileSystemRights
           if($object -eq "Todos") {
                $object = "Everyone"
           }
           log "$server;$ShareName;$object;$permission;NTFS"
        }

        #SMB
        $Share = Get-WmiObject win32_LogicalShareSecuritySetting -Filter "name='$ShareName'" -ComputerName $server
        if($Share) {
            $obj = @()
            $ACLS = $Share.GetSecurityDescriptor().Descriptor.DACL
            foreach($ACL in $ACLS){
                $User = $ACL.Trustee.Name
                if(!($user)){$user = $ACL.Trustee.SID}
                $Domain = $ACL.Trustee.Domain
                switch($ACL.AccessMask) {
                    2032127 {$Perm = "Full Control"}
                    1245631 {$Perm = "Change"}
                    1179817 {$Perm = "Read"}
                }
                $object = "$user"
                if($Domain) {
                    $object = "$Domain\$user"
                }
                log "$server;$ShareName;$object;$Perm;SMB"
            }
        }

    }

    $count++

}