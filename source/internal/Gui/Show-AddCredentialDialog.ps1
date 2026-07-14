# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# GUI-driven credential entry (the "Add credential" modal on the Safehouse page).
# Builds the list of vault entries from collected field values, and a WPF dialog
# to collect them, styled on the same design tokens as the main window.
# New-AddCredentialEntries is kept pure so it can be unit-tested without a UI;
# Show-AddCredentialDialog drives the actual window.

function New-AddCredentialEntries {
    <#
    .SYNOPSIS
        Pure builder: turns collected dialog field values into the vault entry list that
        Save-SafehouseCredentialSet stores. No UI, no side effects — unit-testable.
    .PARAMETER Environment
        'microsoftGraph' or 'googleWorkspace'.
    .PARAMETER Fields
        Hashtable of the raw field values from the dialog.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][hashtable]$Fields
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    switch ($Environment) {
        'microsoftGraph' {
            $entries.Add(@{ VaultKey = 'GUERRILLA_GRAPH_TENANT'; Value = $Fields.TenantId; Type = 'tenantId'
                Environment = 'microsoftGraph'; Description = 'Entra ID Tenant ID'; Identity = $Fields.TenantId })
            $entries.Add(@{ VaultKey = 'GUERRILLA_GRAPH_CLIENTID'; Value = $Fields.ClientId; Type = 'clientId'
                Environment = 'microsoftGraph'; Description = 'App Registration Client ID'; Identity = $Fields.ClientId })
            $secret = @{ VaultKey = 'GUERRILLA_GRAPH_SECRET'; Value = $Fields.ClientSecret; Type = 'clientSecret'
                Environment = 'microsoftGraph'; Description = 'Microsoft Graph Client Secret' }
            if ($Fields.Expiration) { $secret.ExpirationDate = $Fields.Expiration }
            $entries.Add($secret)
        }
        'googleWorkspace' {
            $entries.Add(@{ VaultKey = 'GUERRILLA_GWS_SA'; Value = $Fields.ServiceAccountJson; Type = 'serviceAccount'
                Environment = 'googleWorkspace'; Description = 'Google Workspace service account'; Identity = $Fields.SaClientEmail })
            $entries.Add(@{ VaultKey = 'GUERRILLA_GWS_SA_ADMIN_EMAIL'; Value = $Fields.AdminEmail; Type = 'adminEmail'
                Environment = 'googleWorkspace'; Description = 'Google Workspace delegated-admin email'; Identity = $Fields.AdminEmail })
        }
    }
    return $entries
}

function Test-AddCredentialFields {
    <#
    .SYNOPSIS
        Validates collected dialog values; returns an array of human-readable error
        strings (empty array = valid). Pure — unit-testable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][hashtable]$Fields
    )

    $errs = [System.Collections.Generic.List[string]]::new()
    $guid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    switch ($Environment) {
        'microsoftGraph' {
            if ("$($Fields.TenantId)" -notmatch $guid) { $errs.Add('Tenant ID must be a GUID.') }
            if ("$($Fields.ClientId)" -notmatch $guid) { $errs.Add('Client ID must be a GUID.') }
            if (-not "$($Fields.ClientSecret)") { $errs.Add('Client Secret is required.') }
            if ($Fields.Expiration -and "$($Fields.Expiration)" -notmatch '^\d{4}-\d{2}-\d{2}$') {
                $errs.Add('Secret expiry must be YYYY-MM-DD (or left blank).')
            }
        }
        'googleWorkspace' {
            if (-not "$($Fields.ServiceAccountJson)") { $errs.Add('Service account JSON is required.') }
            elseif (-not $Fields.SaClientEmail)       { $errs.Add('Service account JSON is not valid (no client_email).') }
            if ("$($Fields.AdminEmail)" -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $errs.Add('A valid admin email is required.') }
        }
        default { $errs.Add("Unknown environment '$Environment'.") }
    }
    return @($errs)
}

function Show-AddCredentialDialog {
    <#
    .SYNOPSIS
        Modal WPF dialog to add Entra (Graph) or Google Workspace credentials to the vault.
        Returns the entry list to store (for Save-SafehouseCredentialSet), or $null if the
        user cancelled.
    .PARAMETER Owner
        Owning window (centers the dialog over it).
    .PARAMETER Theme
        'Light' or 'Dark'. Applies the matching Get-GuerrillaGuiTheme palette so the
        modal matches whatever theme the main window is currently showing.
    #>
    [CmdletBinding()]
    param(
        $Owner,
        [ValidateSet('Light', 'Dark')]
        [string]$Theme = 'Light'
    )

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Add credential" Width="560" Height="560"
        WindowStyle="None" ResizeMode="NoResize" AllowsTransparency="False"
        WindowStartupLocation="CenterOwner"
        Background="{DynamicResource BgBrush}"
        UseLayoutRounding="True" SnapsToDevicePixels="True"
        TextOptions.TextFormattingMode="Display"
        FontFamily="Segoe UI Variable Text, Segoe UI" FontSize="13"
        Foreground="{DynamicResource TextBrush}">
  <WindowChrome.WindowChrome>
    <WindowChrome CaptionHeight="48" ResizeBorderThickness="0"
                  GlassFrameThickness="0,0,0,1" CornerRadius="0" UseAeroCaptionButtons="False"/>
  </WindowChrome.WindowChrome>
  <Window.Resources>
    <!-- Light defaults; overwritten from Get-GuerrillaGuiTheme after load. -->
    <SolidColorBrush x:Key="BgBrush"          Color="#FFFFFF"/>
    <SolidColorBrush x:Key="SurfaceBrush"     Color="#F5F5F7"/>
    <SolidColorBrush x:Key="SurfaceAltBrush"  Color="#E8E8ED"/>
    <SolidColorBrush x:Key="TextBrush"        Color="#1D1D1F"/>
    <SolidColorBrush x:Key="HeadingBrush"     Color="#1D1D1F"/>
    <SolidColorBrush x:Key="MutedBrush"       Color="#515154"/>
    <SolidColorBrush x:Key="AccentBrush"      Color="#0066CC"/>
    <SolidColorBrush x:Key="AccentHoverBrush" Color="#1274DB"/>
    <SolidColorBrush x:Key="OnAccentBrush"    Color="#FFFFFF"/>
    <SolidColorBrush x:Key="LineBrush"        Color="#D2D2D7"/>
    <SolidColorBrush x:Key="LineStrongBrush"  Color="#76767C"/>
    <SolidColorBrush x:Key="FocusBrush"       Color="#0066CC"/>
    <SolidColorBrush x:Key="BadBrush"         Color="#B32424"/>

    <Style x:Key="Pill" TargetType="Button">
      <Setter Property="Background" Value="{DynamicResource AccentBrush}"/>
      <Setter Property="Foreground" Value="{DynamicResource OnAccentBrush}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="18,8"/>
      <Setter Property="FontWeight" Value="Medium"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="980"
                    Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{DynamicResource AccentHoverBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="PillGhost" TargetType="Button">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="980"
                    BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}"
                    Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{DynamicResource SurfaceBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="SegPill" TargetType="RadioButton">
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="bd" CornerRadius="980" Background="Transparent"
                    BorderBrush="{DynamicResource LineBrush}" BorderThickness="1"
                    Padding="14,6" SnapsToDevicePixels="True">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bd" Property="Background" Value="{DynamicResource SurfaceBrush}"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="bd" Property="Background" Value="{DynamicResource AccentBrush}"/>
                <Setter TargetName="bd" Property="BorderBrush" Value="{DynamicResource AccentBrush}"/>
                <Setter Property="Foreground" Value="{DynamicResource OnAccentBrush}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="{DynamicResource MutedBrush}"/>
      <Setter Property="Margin" Value="0,10,0,4"/>
      <Setter Property="FontSize" Value="12"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{DynamicResource BgBrush}"/>
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="CaretBrush" Value="{DynamicResource TextBrush}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8" SnapsToDevicePixels="True">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsKeyboardFocusWithin" Value="True">
          <Setter Property="BorderBrush" Value="{DynamicResource FocusBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="PasswordBox">
      <Setter Property="Background" Value="{DynamicResource BgBrush}"/>
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="CaretBrush" Value="{DynamicResource TextBrush}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="PasswordBox">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8" SnapsToDevicePixels="True">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsKeyboardFocusWithin" Value="True">
          <Setter Property="BorderBrush" Value="{DynamicResource FocusBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
  </Window.Resources>

  <Border BorderBrush="{DynamicResource LineBrush}" BorderThickness="1" Background="{DynamicResource BgBrush}">
    <Grid Margin="24,0,24,20">
      <Grid.RowDefinitions>
        <RowDefinition Height="48"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
      </Grid.RowDefinitions>

      <Grid Grid.Row="0">
        <TextBlock Text="Add a credential to the Safehouse" FontSize="15" FontWeight="SemiBold"
                   Foreground="{DynamicResource HeadingBrush}" VerticalAlignment="Center" Margin="0"/>
      </Grid>

      <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,8,0,4">
        <RadioButton x:Name="rb_Entra" Content="Microsoft Entra / Graph" GroupName="Env" IsChecked="True"
                     Style="{StaticResource SegPill}"/>
        <RadioButton x:Name="rb_Gws" Content="Google Workspace" GroupName="Env"
                     Style="{StaticResource SegPill}"/>
      </StackPanel>

      <Grid Grid.Row="3" VerticalAlignment="Top">
        <!-- Entra panel -->
        <StackPanel x:Name="panel_Entra" Visibility="Visible">
          <TextBlock Text="Tenant ID (GUID)"/>
          <TextBox x:Name="tb_Tenant"/>
          <TextBlock Text="Application (Client) ID (GUID)"/>
          <TextBox x:Name="tb_ClientId"/>
          <TextBlock Text="Client Secret"/>
          <PasswordBox x:Name="pb_Secret"/>
          <TextBlock Text="Secret expiry (YYYY-MM-DD, optional)"/>
          <TextBox x:Name="tb_Expiry"/>
        </StackPanel>
        <!-- Google Workspace panel -->
        <StackPanel x:Name="panel_Gws" Visibility="Collapsed">
          <TextBlock Text="Service account JSON key file"/>
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBox x:Name="tb_SaPath" Grid.Column="0"/>
            <Button x:Name="btn_Browse" Grid.Column="1" Content="Browse" Style="{StaticResource PillGhost}"
                    Margin="8,0,0,0"/>
          </Grid>
          <TextBlock Text="Delegated-admin email (a Super Admin)"/>
          <TextBox x:Name="tb_AdminEmail"/>
          <TextBlock Text="The service account needs domain-wide delegation configured in the Google Admin Console."
                     TextWrapping="Wrap" Margin="0,12,0,0"/>
        </StackPanel>
      </Grid>

      <TextBlock x:Name="tb_Error" Grid.Row="4" Foreground="{DynamicResource BadBrush}" TextWrapping="Wrap"
                 Margin="0,10,0,0" FontSize="12"/>

      <StackPanel Grid.Row="5" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
        <Button x:Name="btn_Cancel" Content="Cancel" Style="{StaticResource PillGhost}" Margin="0,0,8,0"/>
        <Button x:Name="btn_Save" Content="Save credential" Style="{StaticResource Pill}"/>
      </StackPanel>
    </Grid>
  </Border>
</Window>
'@

    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $win = [System.Windows.Markup.XamlReader]::Load($reader)
    if ($Owner) { $win.Owner = $Owner }

    # Match the main window's current theme by overwriting the brush resources.
    try {
        $palettes = Get-GuerrillaGuiTheme
        $pal = if ($Theme -eq 'Dark') { $palettes.Dark } else { $palettes.Light }
        foreach ($key in $pal.Keys) {
            if ($win.Resources.Contains("${key}Brush")) {
                $color = [System.Windows.Media.ColorConverter]::ConvertFromString($pal[$key])
                $brush = [System.Windows.Media.SolidColorBrush]::new($color)
                $brush.Freeze()
                $win.Resources["${key}Brush"] = $brush
            }
        }
    } catch { }

    $ctl = @{}
    foreach ($n in 'rb_Entra', 'rb_Gws', 'panel_Entra', 'panel_Gws', 'tb_Tenant', 'tb_ClientId',
        'pb_Secret', 'tb_Expiry', 'tb_SaPath', 'btn_Browse', 'tb_AdminEmail', 'tb_Error', 'btn_Cancel', 'btn_Save') {
        $ctl[$n] = $win.FindName($n)
    }

    $ctl.rb_Entra.Add_Checked({ $ctl.panel_Entra.Visibility = 'Visible'; $ctl.panel_Gws.Visibility = 'Collapsed' }.GetNewClosure())
    $ctl.rb_Gws.Add_Checked({ $ctl.panel_Entra.Visibility = 'Collapsed'; $ctl.panel_Gws.Visibility = 'Visible' }.GetNewClosure())

    $ctl.btn_Browse.Add_Click({
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Service account JSON (*.json)|*.json|All files (*.*)|*.*'
        if ($dlg.ShowDialog()) { $ctl.tb_SaPath.Text = $dlg.FileName }
    }.GetNewClosure())

    $result = @{ Entries = $null }

    # Borderless window: no system close button, so wire the keyboard equivalents.
    $ctl.btn_Cancel.IsCancel = $true    # Esc closes
    $ctl.btn_Save.IsDefault  = $true    # Enter saves

    $ctl.btn_Cancel.Add_Click({ $win.Close() }.GetNewClosure())

    $ctl.btn_Save.Add_Click({
        $env = if ($ctl.rb_Gws.IsChecked) { 'googleWorkspace' } else { 'microsoftGraph' }
        $fields = @{}
        if ($env -eq 'microsoftGraph') {
            $fields.TenantId     = $ctl.tb_Tenant.Text.Trim()
            $fields.ClientId     = $ctl.tb_ClientId.Text.Trim()
            $fields.ClientSecret = $ctl.pb_Secret.Password
            $fields.Expiration   = $ctl.tb_Expiry.Text.Trim()
        } else {
            $saPath = $ctl.tb_SaPath.Text.Trim()
            $fields.ServiceAccountJson = $null; $fields.SaClientEmail = $null
            if ($saPath -and (Test-Path $saPath)) {
                try {
                    $raw = Get-Content -Path $saPath -Raw
                    $sa = $raw | ConvertFrom-Json
                    $fields.ServiceAccountJson = $raw
                    $fields.SaClientEmail = $sa.client_email
                } catch { }
            }
            $fields.AdminEmail = $ctl.tb_AdminEmail.Text.Trim()
        }

        $errs = Test-AddCredentialFields -Environment $env -Fields $fields
        if ($errs.Count -gt 0) {
            $ctl.tb_Error.Text = ($errs -join '  ')
            return
        }
        $result.Entries = New-AddCredentialEntries -Environment $env -Fields $fields
        $win.Close()
    }.GetNewClosure())

    [void]$win.ShowDialog()
    return $result.Entries
}
