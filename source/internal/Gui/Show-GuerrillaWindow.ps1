# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Show-GuerrillaWindow {
    <#
    .SYNOPSIS
        Internal builder for the Show-Guerrilla WPF window.
    .DESCRIPTION
        Defines the window XAML, parses it, wires up event handlers for each
        page, and blocks until the user closes the window. Public entry point is
        Show-Guerrilla in public\.

        Design notes: the window is borderless (WindowChrome custom title bar)
        and styled after the guerrilla.army design tokens — flat gray surfaces,
        pill buttons, 12px card radius, system fonts, and a light/dark theme
        toggle. All colors resolve through DynamicResource brushes named
        <Token>Brush so Get-GuerrillaGuiTheme palettes can be swapped live.

        The Run page is deliberately simple: one card and one button per
        platform, defaults that just work, and an Options drawer for everything
        else. Every action remains a wrapper around the public cmdlets.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName  = 'Guerrilla',
        [string]$ConfigPath,
        [ValidateSet('Operations', 'Safehouse', 'Reports', 'Settings', 'Source', 'Branding')]
        [string]$StartOn    = 'Operations',
        [Parameter(Mandatory)]
        [string]$ModulePath
    )

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

    $palettes    = Get-GuerrillaGuiTheme
    $reportsDir  = Join-Path (Get-GuerrillaDataRoot) 'Reports'

    # XAML for the entire window. Bound at parse time — no runtime DataBinding.
    # Naming convention: x:Name="<page>_<purpose>" so handlers stay greppable.
    # Every color is a DynamicResource so the theme toggle can swap palettes live;
    # the literal values below are the light palette (the parse-time default).
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Guerrilla"
        Height="760" Width="1180"
        MinHeight="600" MinWidth="940"
        WindowStyle="None" ResizeMode="CanResize" AllowsTransparency="False"
        Background="{DynamicResource BgBrush}"
        WindowStartupLocation="CenterScreen"
        UseLayoutRounding="True" SnapsToDevicePixels="True"
        TextOptions.TextFormattingMode="Display" TextOptions.TextRenderingMode="ClearType"
        FontFamily="Segoe UI Variable Text, Segoe UI" FontSize="13"
        Foreground="{DynamicResource TextBrush}">
  <WindowChrome.WindowChrome>
    <WindowChrome CaptionHeight="56" ResizeBorderThickness="6"
                  GlassFrameThickness="0,0,0,1" CornerRadius="0" UseAeroCaptionButtons="False"/>
  </WindowChrome.WindowChrome>
  <Window.Resources>
    <!-- ═══ Palette (light defaults; swapped live by the theme toggle) ═══ -->
    <SolidColorBrush x:Key="BgBrush"          Color="#FFFFFF"/>
    <SolidColorBrush x:Key="SurfaceBrush"     Color="#F5F5F7"/>
    <SolidColorBrush x:Key="SurfaceAltBrush"  Color="#E8E8ED"/>
    <SolidColorBrush x:Key="TextBrush"        Color="#1D1D1F"/>
    <SolidColorBrush x:Key="HeadingBrush"     Color="#1D1D1F"/>
    <SolidColorBrush x:Key="MutedBrush"       Color="#515154"/>
    <SolidColorBrush x:Key="LinkBrush"        Color="#0066CC"/>
    <SolidColorBrush x:Key="LinkHoverBrush"   Color="#0050A0"/>
    <SolidColorBrush x:Key="AccentBrush"      Color="#0066CC"/>
    <SolidColorBrush x:Key="AccentHoverBrush" Color="#1274DB"/>
    <SolidColorBrush x:Key="OnAccentBrush"    Color="#FFFFFF"/>
    <SolidColorBrush x:Key="LineBrush"        Color="#D2D2D7"/>
    <SolidColorBrush x:Key="LineStrongBrush"  Color="#76767C"/>
    <SolidColorBrush x:Key="FocusBrush"       Color="#0066CC"/>
    <SolidColorBrush x:Key="OkBrush"          Color="#207A4E"/>
    <SolidColorBrush x:Key="WarnBrush"        Color="#9A4A05"/>
    <SolidColorBrush x:Key="BadBrush"         Color="#B32424"/>
    <SolidColorBrush x:Key="CodeBgBrush"      Color="#F5F5F7"/>

    <!-- ═══ Nav links (header) ═══ -->
    <Style x:Key="NavLink" TargetType="Button">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="{DynamicResource MutedBrush}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="WindowChrome.IsHitTestVisibleInChrome" Value="True"/>
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
          <Setter Property="Foreground" Value="{DynamicResource HeadingBrush}"/>
          <Setter Property="Background" Value="{DynamicResource SurfaceBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="NavLinkActive" TargetType="Button" BasedOn="{StaticResource NavLink}">
      <Setter Property="Foreground" Value="{DynamicResource LinkBrush}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
    </Style>

    <!-- ═══ Pill buttons ═══ -->
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
        <Trigger Property="IsEnabled" Value="False">
          <Setter Property="Background" Value="{DynamicResource SurfaceAltBrush}"/>
          <Setter Property="Foreground" Value="{DynamicResource MutedBrush}"/>
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
        <Trigger Property="IsEnabled" Value="False">
          <Setter Property="Foreground" Value="{DynamicResource MutedBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <!-- ═══ Window control buttons ═══ -->
    <Style x:Key="WinBtn" TargetType="Button">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="{DynamicResource MutedBrush}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Width" Value="40"/>
      <Setter Property="Height" Value="30"/>
      <Setter Property="FontFamily" Value="Segoe MDL2 Assets"/>
      <Setter Property="FontSize" Value="10"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="WindowChrome.IsHitTestVisibleInChrome" Value="True"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="8" SnapsToDevicePixels="True">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{DynamicResource SurfaceAltBrush}"/>
          <Setter Property="Foreground" Value="{DynamicResource HeadingBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="WinBtnClose" TargetType="Button" BasedOn="{StaticResource WinBtn}">
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{DynamicResource BadBrush}"/>
          <Setter Property="Foreground" Value="{DynamicResource OnAccentBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- ═══ Cards ═══ -->
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="{DynamicResource SurfaceBrush}"/>
      <Setter Property="CornerRadius" Value="12"/>
      <Setter Property="Padding" Value="20"/>
    </Style>
    <Style x:Key="CardHover" TargetType="Border" BasedOn="{StaticResource Card}">
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{DynamicResource SurfaceAltBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- ═══ Inputs ═══ -->
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{DynamicResource BgBrush}"/>
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource LineBrush}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="CaretBrush" Value="{DynamicResource TextBrush}"/>
      <Setter Property="SelectionBrush" Value="{DynamicResource AccentBrush}"/>
      <!-- Single-line inputs center their text; the multiline log/source panes
           override VerticalContentAlignment to Stretch so text fills from the top. -->
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8" SnapsToDevicePixels="True">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"
                            VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
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

    <!-- Full template ComboBox: the stock closed-box chrome ignores Foreground under
         some system themes, so the selection box is themed explicitly here. -->
    <Style TargetType="ComboBox">
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="Height" Value="32"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid>
              <ToggleButton x:Name="ToggleButton" Focusable="False" ClickMode="Press"
                            IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}">
                <ToggleButton.Template>
                  <ControlTemplate TargetType="ToggleButton">
                    <Border x:Name="bd" Background="{DynamicResource BgBrush}" BorderBrush="{DynamicResource LineBrush}"
                            BorderThickness="1" CornerRadius="8" SnapsToDevicePixels="True">
                      <Grid>
                        <Grid.ColumnDefinitions>
                          <ColumnDefinition Width="*"/>
                          <ColumnDefinition Width="24"/>
                        </Grid.ColumnDefinitions>
                        <Path Grid.Column="1" HorizontalAlignment="Center" VerticalAlignment="Center"
                              Data="M 0 0 L 4 4 L 8 0 Z" Fill="{DynamicResource MutedBrush}"/>
                      </Grid>
                    </Border>
                    <ControlTemplate.Triggers>
                      <Trigger Property="IsMouseOver" Value="True">
                        <Setter TargetName="bd" Property="Background" Value="{DynamicResource SurfaceBrush}"/>
                      </Trigger>
                    </ControlTemplate.Triggers>
                  </ControlTemplate>
                </ToggleButton.Template>
              </ToggleButton>
              <ContentPresenter x:Name="ContentSite" IsHitTestVisible="False"
                                Content="{TemplateBinding SelectionBoxItem}"
                                ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                Margin="12,0,30,0" VerticalAlignment="Center" HorizontalAlignment="Left"
                                TextElement.Foreground="{DynamicResource TextBrush}"/>
              <Popup x:Name="Popup" Placement="Bottom" VerticalOffset="4" Focusable="False" AllowsTransparency="True"
                     IsOpen="{TemplateBinding IsDropDownOpen}" PopupAnimation="Fade">
                <Grid MaxHeight="{TemplateBinding MaxDropDownHeight}"
                      MinWidth="{Binding ActualWidth, RelativeSource={RelativeSource TemplatedParent}}">
                  <Border Background="{DynamicResource BgBrush}" BorderBrush="{DynamicResource LineBrush}"
                          BorderThickness="1" CornerRadius="10" Padding="4">
                    <ScrollViewer SnapsToDevicePixels="True">
                      <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained"/>
                    </ScrollViewer>
                  </Border>
                </Grid>
              </Popup>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ComboBoxItem">
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="Padding" Value="10,6"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBoxItem">
            <Border x:Name="bd" Background="Transparent" CornerRadius="7"
                    Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsHighlighted" Value="True">
                <Setter TargetName="bd" Property="Background" Value="{DynamicResource SurfaceAltBrush}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- ═══ Check / radio ═══ -->
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="Margin" Value="0,4,18,4"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <StackPanel Orientation="Horizontal" Background="Transparent">
              <Border x:Name="box" Width="18" Height="18" CornerRadius="5"
                      Background="{DynamicResource BgBrush}"
                      BorderBrush="{DynamicResource LineStrongBrush}" BorderThickness="1.5"
                      VerticalAlignment="Center" SnapsToDevicePixels="True">
                <Path x:Name="check" Data="M 3.5 9 L 7.5 12.5 L 13.5 4.5"
                      Stroke="{DynamicResource OnAccentBrush}" StrokeThickness="2"
                      StrokeStartLineCap="Round" StrokeEndLineCap="Round" StrokeLineJoin="Round"
                      Visibility="Collapsed"/>
              </Border>
              <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center" RecognizesAccessKey="True"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource AccentBrush}"/>
              </Trigger>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="box" Property="Background" Value="{DynamicResource AccentBrush}"/>
                <Setter TargetName="box" Property="BorderBrush" Value="{DynamicResource AccentBrush}"/>
                <Setter TargetName="check" Property="Visibility" Value="Visible"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Segmented pill (used for Fast / Full scan depth) -->
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

    <!-- ═══ Scrollbars (thin, rounded, no arrows) ═══ -->
    <Style x:Key="ScrollThumb" TargetType="Thumb">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Thumb">
            <Border Background="{DynamicResource LineStrongBrush}" CornerRadius="4" Opacity="0.45" Margin="2"/>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Width" Value="10"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ScrollBar">
            <Grid Background="Transparent">
              <Track x:Name="PART_Track" IsDirectionReversed="True">
                <Track.DecreaseRepeatButton>
                  <RepeatButton Command="ScrollBar.PageUpCommand" Opacity="0" Focusable="False"/>
                </Track.DecreaseRepeatButton>
                <Track.IncreaseRepeatButton>
                  <RepeatButton Command="ScrollBar.PageDownCommand" Opacity="0" Focusable="False"/>
                </Track.IncreaseRepeatButton>
                <Track.Thumb>
                  <Thumb Style="{StaticResource ScrollThumb}"/>
                </Track.Thumb>
              </Track>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Width" Value="Auto"/>
          <Setter Property="Height" Value="10"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="ScrollBar">
                <Grid Background="Transparent">
                  <Track x:Name="PART_Track" IsDirectionReversed="False">
                    <Track.DecreaseRepeatButton>
                      <RepeatButton Command="ScrollBar.PageLeftCommand" Opacity="0" Focusable="False"/>
                    </Track.DecreaseRepeatButton>
                    <Track.IncreaseRepeatButton>
                      <RepeatButton Command="ScrollBar.PageRightCommand" Opacity="0" Focusable="False"/>
                    </Track.IncreaseRepeatButton>
                    <Track.Thumb>
                      <Thumb Style="{StaticResource ScrollThumb}"/>
                    </Track.Thumb>
                  </Track>
                </Grid>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- ═══ Data grid (quiet table: horizontal rules only) ═══ -->
    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="{DynamicResource LineBrush}"/>
      <Setter Property="RowBackground" Value="Transparent"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="CanUserDeleteRows" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="SelectionMode" Value="Single"/>
      <Setter Property="SelectionUnit" Value="FullRow"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="{DynamicResource MutedBrush}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Padding" Value="10,8"/>
      <Setter Property="BorderBrush" Value="{DynamicResource LineStrongBrush}"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
    <Style TargetType="DataGridRow">
      <Setter Property="Background" Value="Transparent"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{DynamicResource SurfaceBrush}"/>
        </Trigger>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="{DynamicResource SurfaceAltBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="Padding" Value="10,8"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="Transparent"/>
          <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- ═══ Lists ═══ -->
    <Style TargetType="ListBox">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Disabled"/>
    </Style>
    <Style TargetType="ListBoxItem">
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListBoxItem">
            <Border x:Name="bd" Background="Transparent" CornerRadius="8" Padding="10,7" Margin="2,1"
                    SnapsToDevicePixels="True">
              <ContentPresenter/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bd" Property="Background" Value="{DynamicResource SurfaceBrush}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="bd" Property="Background" Value="{DynamicResource SurfaceAltBrush}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- ═══ Tooltip ═══ -->
    <Style TargetType="ToolTip">
      <Setter Property="Background" Value="{DynamicResource BgBrush}"/>
      <Setter Property="Foreground" Value="{DynamicResource TextBrush}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource LineBrush}"/>
      <Setter Property="Padding" Value="10,7"/>
      <Setter Property="MaxWidth" Value="420"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToolTip">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1" CornerRadius="8" Padding="{TemplateBinding Padding}">
              <ContentPresenter/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- Options drawer toggle: text link with a rotating chevron -->
    <Style x:Key="DrawerToggle" TargetType="ToggleButton">
      <Setter Property="Foreground" Value="{DynamicResource LinkBrush}"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToggleButton">
            <StackPanel Orientation="Horizontal" Background="Transparent">
              <Path x:Name="chev" Data="M 0 0 L 4 4 L 0 8" Stroke="{DynamicResource LinkBrush}"
                    StrokeThickness="1.6" StrokeStartLineCap="Round" StrokeEndLineCap="Round"
                    VerticalAlignment="Center" Margin="2,1,8,0"
                    RenderTransformOrigin="0.5,0.5"/>
              <ContentPresenter VerticalAlignment="Center"/>
            </StackPanel>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="chev" Property="RenderTransform">
                  <Setter.Value>
                    <RotateTransform Angle="90"/>
                  </Setter.Value>
                </Setter>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <!-- ═══ Root chrome ═══ -->
  <Border x:Name="rootChrome" Background="{DynamicResource BgBrush}"
          BorderBrush="{DynamicResource LineBrush}" BorderThickness="1">
    <DockPanel>

      <!-- ═══ Header (draggable caption area) ═══ -->
      <Border DockPanel.Dock="Top" Height="56" Background="{DynamicResource BgBrush}"
              BorderBrush="{DynamicResource LineBrush}" BorderThickness="0,0,0,1">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Guerrilla" FontSize="17" FontWeight="SemiBold"
                     Foreground="{DynamicResource HeadingBrush}" VerticalAlignment="Center" Margin="22,0,0,0"/>
          <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" Margin="26,0,0,0">
            <Button x:Name="nav_Operations" Content="Run"       Style="{StaticResource NavLink}"/>
            <Button x:Name="nav_Reports"    Content="Reports"   Style="{StaticResource NavLink}" Margin="2,0,0,0"/>
            <Button x:Name="nav_Safehouse"  Content="Safehouse" Style="{StaticResource NavLink}" Margin="2,0,0,0"/>
            <Button x:Name="nav_Settings"   Content="Settings"  Style="{StaticResource NavLink}" Margin="2,0,0,0"/>
            <Button x:Name="nav_Source"     Content="Inspector" Style="{StaticResource NavLink}" Margin="2,0,0,0"/>
            <Button x:Name="nav_Branding"   Content="Branding"  Style="{StaticResource NavLink}" Margin="2,0,0,0"/>
          </StackPanel>
          <Button Grid.Column="3" x:Name="hdr_ThemeToggle" Style="{StaticResource WinBtn}"
                  FontFamily="Segoe UI Symbol" FontSize="14" Margin="0,0,6,0"/>
          <StackPanel Grid.Column="4" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,10,0">
            <Button x:Name="hdr_Min"   Style="{StaticResource WinBtn}"/>
            <Button x:Name="hdr_Max"   Style="{StaticResource WinBtn}"/>
            <Button x:Name="hdr_Close" Style="{StaticResource WinBtnClose}"/>
          </StackPanel>
        </Grid>
      </Border>

      <!-- ═══ Footer ═══ -->
      <Border DockPanel.Dock="Bottom" BorderBrush="{DynamicResource LineBrush}" BorderThickness="0,1,0,0"
              Padding="22,8">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" x:Name="foot_Info" Foreground="{DynamicResource MutedBrush}" FontSize="11"/>
          <StackPanel Grid.Column="2" Orientation="Horizontal">
            <TextBlock Text="Free and open source" Foreground="{DynamicResource MutedBrush}" FontSize="11" Margin="0,0,12,0"/>
            <TextBlock x:Name="foot_Site" Text="guerrilla.army" Foreground="{DynamicResource LinkBrush}"
                       FontSize="11" Cursor="Hand"/>
          </StackPanel>
        </Grid>
      </Border>

      <!-- ═══ Pages ═══ -->
      <Grid Margin="32,20,32,20">

        <!-- ─── RUN (Operations) ─── -->
        <Grid x:Name="panel_Operations" Visibility="Visible">

          <!-- Home: hero + one card per platform -->
          <ScrollViewer x:Name="ops_Home" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
            <StackPanel MaxWidth="1000" Margin="0,14,0,28">
              <TextBlock Text="Audit your environment." FontSize="30" FontWeight="Bold"
                         Foreground="{DynamicResource HeadingBrush}"/>
              <TextBlock Margin="0,10,0,0" FontSize="14" TextWrapping="Wrap"
                         Foreground="{DynamicResource MutedBrush}"
                         Text="One click per platform. Every check is read-only, every verdict carries evidence, and the HTML report opens when the run completes."/>

              <Grid Margin="0,28,0,0">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <Border Grid.Column="0" Style="{StaticResource CardHover}" Margin="0,0,16,0">
                  <Grid>
                    <Grid.RowDefinitions>
                      <RowDefinition Height="Auto"/>
                      <RowDefinition Height="*"/>
                      <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <TextBlock Grid.Row="0" Text="Active Directory" FontSize="15" FontWeight="SemiBold"
                               Foreground="{DynamicResource HeadingBrush}"/>
                    <TextBlock Grid.Row="1" Margin="0,6,0,16" FontSize="12" TextWrapping="Wrap"
                               Foreground="{DynamicResource MutedBrush}"
                               Text="Domain and forest posture, Kerberos, delegation, Tier Zero, GPOs and more. Runs as your current domain user; no stored credential needed."/>
                    <Button Grid.Row="2" x:Name="run_AD" Content="Run audit" Style="{StaticResource Pill}"
                            HorizontalAlignment="Left"/>
                  </Grid>
                </Border>

                <Border Grid.Column="1" Style="{StaticResource CardHover}" Margin="0,0,16,0">
                  <Grid>
                    <Grid.RowDefinitions>
                      <RowDefinition Height="Auto"/>
                      <RowDefinition Height="*"/>
                      <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <TextBlock Grid.Row="0" Text="Entra / Azure / M365" FontSize="15" FontWeight="SemiBold"
                               Foreground="{DynamicResource HeadingBrush}"/>
                    <TextBlock Grid.Row="1" Margin="0,6,0,16" FontSize="12" TextWrapping="Wrap"
                               Foreground="{DynamicResource MutedBrush}"
                               Text="Conditional Access, authentication methods, PIM, applications, Exchange and tenant posture. Uses the app credential stored in your Safehouse."/>
                    <Button Grid.Row="2" x:Name="run_Cloud" Content="Run audit" Style="{StaticResource Pill}"
                            HorizontalAlignment="Left"/>
                  </Grid>
                </Border>

                <Border Grid.Column="2" Style="{StaticResource CardHover}">
                  <Grid>
                    <Grid.RowDefinitions>
                      <RowDefinition Height="Auto"/>
                      <RowDefinition Height="*"/>
                      <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <TextBlock Grid.Row="0" Text="Google Workspace" FontSize="15" FontWeight="SemiBold"
                               Foreground="{DynamicResource HeadingBrush}"/>
                    <TextBlock Grid.Row="1" Margin="0,6,0,16" FontSize="12" TextWrapping="Wrap"
                               Foreground="{DynamicResource MutedBrush}"
                               Text="Authentication, Drive, OAuth, admin management and K12 student posture. Uses the service account stored in your Safehouse."/>
                    <Button Grid.Row="2" x:Name="run_GWS" Content="Run audit" Style="{StaticResource Pill}"
                            HorizontalAlignment="Left"/>
                  </Grid>
                </Border>
              </Grid>

              <Border Style="{StaticResource CardHover}" Margin="0,16,0,0">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <StackPanel Grid.Column="0" VerticalAlignment="Center">
                    <TextBlock Text="Campaign" FontSize="15" FontWeight="SemiBold"
                               Foreground="{DynamicResource HeadingBrush}"/>
                    <TextBlock Margin="0,6,0,0" FontSize="12" TextWrapping="Wrap"
                               Foreground="{DynamicResource MutedBrush}"
                               Text="Every platform in sequence, one combined report, and a delta against your previous run."/>
                  </StackPanel>
                  <Button Grid.Column="1" x:Name="run_Campaign" Content="Run everything"
                          Style="{StaticResource Pill}" VerticalAlignment="Center" Margin="20,0,0,0"/>
                </Grid>
              </Border>

              <!-- Options drawer -->
              <ToggleButton x:Name="opt_Toggle" Content="Options" Style="{StaticResource DrawerToggle}"
                            Margin="4,22,0,0" HorizontalAlignment="Left"/>
              <Border x:Name="opt_Panel" Style="{StaticResource Card}" Margin="0,12,0,0" Padding="24"
                      Visibility="Collapsed">
                <StackPanel>
                  <Grid>
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="Auto"/>
                      <ColumnDefinition Width="*"/>
                      <ColumnDefinition Width="Auto"/>
                      <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                      <TextBlock Text="Scan depth" Foreground="{DynamicResource MutedBrush}" FontSize="12"
                                 VerticalAlignment="Center" Margin="0,0,12,0"/>
                      <RadioButton x:Name="ops_ModeFast" Content="Fast" GroupName="Mode" IsChecked="True"
                                   Style="{StaticResource SegPill}"/>
                      <RadioButton x:Name="ops_ModeFull" Content="Full" GroupName="Mode"
                                   Style="{StaticResource SegPill}"/>
                    </StackPanel>
                    <TextBlock Grid.Column="2" Text="Report style" Foreground="{DynamicResource MutedBrush}"
                               FontSize="12" VerticalAlignment="Center" Margin="0,0,10,0"/>
                    <ComboBox Grid.Column="3" x:Name="ops_ReportStyle" Width="150">
                      <ComboBoxItem Content="Guerrilla" IsSelected="True"/>
                      <ComboBoxItem Content="Professional"/>
                      <ComboBoxItem Content="Slate"/>
                    </ComboBox>
                  </Grid>

                  <WrapPanel Margin="0,16,0,0">
                    <CheckBox x:Name="ops_NoReports" Content="No reports"/>
                    <CheckBox x:Name="ops_NoDelta"   Content="No delta"/>
                    <CheckBox x:Name="ops_TestMode"  Content="Test mode"
                              ToolTip="Simulate a scan with no live connection. Produces an all-fail report so you can preview themes and branding."/>
                  </WrapPanel>

                  <Border Height="1" Background="{DynamicResource LineBrush}" Margin="0,18,0,18"/>

                  <TextBlock Text="Categories" FontWeight="SemiBold" Foreground="{DynamicResource HeadingBrush}"/>
                  <TextBlock Text="Applied to whichever platform you run. Campaign always runs each platform's default set."
                             Foreground="{DynamicResource MutedBrush}" FontSize="12" Margin="0,4,0,10"/>
                  <TextBlock Text="Active Directory" Foreground="{DynamicResource MutedBrush}" FontSize="12"
                             FontWeight="SemiBold" Margin="0,4,0,2"/>
                  <WrapPanel x:Name="opt_CatsAD"/>
                  <TextBlock Text="Entra / Azure / M365" Foreground="{DynamicResource MutedBrush}" FontSize="12"
                             FontWeight="SemiBold" Margin="0,12,0,2"/>
                  <WrapPanel x:Name="opt_CatsCloud"/>
                  <TextBlock Text="Google Workspace" Foreground="{DynamicResource MutedBrush}" FontSize="12"
                             FontWeight="SemiBold" Margin="0,12,0,2"/>
                  <WrapPanel x:Name="opt_CatsGWS"/>

                  <Border Height="1" Background="{DynamicResource LineBrush}" Margin="0,18,0,18"/>

                  <Grid>
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="120"/>
                      <ColumnDefinition Width="*"/>
                      <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                      <RowDefinition Height="Auto"/>
                      <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <TextBlock Grid.Row="0" Grid.Column="0" Text="Student OUs" Foreground="{DynamicResource MutedBrush}"
                               FontSize="12" VerticalAlignment="Center"/>
                    <TextBox Grid.Row="0" Grid.Column="1" Grid.ColumnSpan="2" x:Name="ops_StudentOU"
                             AutomationProperties.Name="Student organizational units"
                             AutomationProperties.HelpText="Comma-separated OU paths that contain student accounts, e.g. /Students. K12 checks that assess student posture require this; without it they report Not Assessed."
                             ToolTip="Comma-separated OU path(s) containing student accounts, e.g. /Students or OU=Students,DC=district,DC=org. Required by the OU-scoped K12 checks; leave empty to skip them (they report Not Assessed)."/>
                    <TextBlock Grid.Row="1" Grid.Column="0" Text="Output" Foreground="{DynamicResource MutedBrush}"
                               FontSize="12" VerticalAlignment="Center" Margin="0,10,0,0"/>
                    <TextBox Grid.Row="1" Grid.Column="1" x:Name="ops_OutputDir" Margin="0,10,0,0"/>
                    <Button Grid.Row="1" Grid.Column="2" x:Name="ops_BrowseOutput" Content="Browse"
                            Style="{StaticResource PillGhost}" Margin="8,10,0,0"/>
                  </Grid>
                </StackPanel>
              </Border>
            </StackPanel>
          </ScrollViewer>

          <!-- Run view: title, live log, result -->
          <Grid x:Name="ops_Run" Visibility="Collapsed" MaxWidth="1000">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*"/>
              <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <Grid Grid.Row="0" Margin="0,10,0,0">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
              </Grid.ColumnDefinitions>
              <StackPanel Grid.Column="0">
                <TextBlock x:Name="run_Title" FontSize="24" FontWeight="Bold"
                           Foreground="{DynamicResource HeadingBrush}"/>
                <TextBlock x:Name="run_Status" Foreground="{DynamicResource MutedBrush}" Margin="0,6,0,0"/>
              </StackPanel>
              <Button Grid.Column="1" x:Name="ops_CancelButton" Content="Cancel"
                      Style="{StaticResource PillGhost}" VerticalAlignment="Top"/>
            </Grid>
            <Border Grid.Row="1" x:Name="ops_Progress" Height="4" CornerRadius="2"
                    Background="{DynamicResource SurfaceAltBrush}" ClipToBounds="True"
                    Margin="0,16,0,0" Visibility="Collapsed">
              <Border x:Name="ops_ProgressDash" Width="180" HorizontalAlignment="Left" CornerRadius="2"
                      Background="{DynamicResource AccentBrush}"/>
            </Border>
            <Border Grid.Row="2" Background="{DynamicResource CodeBgBrush}" CornerRadius="8"
                    Margin="0,16,0,0" Padding="6">
              <TextBox x:Name="ops_LogPane" IsReadOnly="True" VerticalScrollBarVisibility="Auto"
                       HorizontalScrollBarVisibility="Auto" AcceptsReturn="True" TextWrapping="NoWrap"
                       FontFamily="Consolas" FontSize="12" Background="Transparent"
                       VerticalContentAlignment="Stretch"
                       Foreground="{DynamicResource TextBrush}" BorderThickness="0" Padding="8"/>
            </Border>
            <Border Grid.Row="3" x:Name="ops_ResultBanner" Background="{DynamicResource SurfaceBrush}"
                    CornerRadius="12" BorderThickness="3,0,0,0" BorderBrush="{DynamicResource OkBrush}"
                    Padding="16,12" Margin="0,16,0,0" Visibility="Collapsed">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" x:Name="ops_ResultText" VerticalAlignment="Center" TextWrapping="Wrap"
                           Foreground="{DynamicResource TextBrush}"/>
                <Button Grid.Column="1" x:Name="ops_OpenReport" Content="Open report"
                        Style="{StaticResource Pill}" Margin="16,0,0,0" VerticalAlignment="Center"/>
                <Button Grid.Column="2" x:Name="ops_RunAgain" Content="New audit"
                        Style="{StaticResource PillGhost}" Margin="8,0,0,0" VerticalAlignment="Center"/>
              </Grid>
            </Border>
          </Grid>
        </Grid>

        <!-- ─── SAFEHOUSE ─── -->
        <Grid x:Name="panel_Safehouse" Visibility="Collapsed" MaxWidth="1000">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Text="Safehouse" FontSize="24" FontWeight="Bold"
                     Foreground="{DynamicResource HeadingBrush}" Margin="0,10,0,0"/>
          <TextBlock Grid.Row="1" Text="Stored credentials, expiration status, and rotation history."
                     Foreground="{DynamicResource MutedBrush}" Margin="0,6,0,16"/>
          <Border Grid.Row="2" BorderBrush="{DynamicResource LineBrush}" BorderThickness="1" CornerRadius="12"
                  Padding="6" ClipToBounds="True">
            <DataGrid x:Name="sh_Grid">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Environment"   Binding="{Binding Environment}"    Width="140"/>
                <DataGridTextColumn Header="Description"   Binding="{Binding Description}"    Width="*"/>
                <DataGridTextColumn Header="Identity"      Binding="{Binding Identity}"       Width="220"/>
                <DataGridTextColumn Header="Stored"        Binding="{Binding StoredDate}"     Width="110"/>
                <DataGridTextColumn Header="Expires"       Binding="{Binding ExpirationDate}" Width="110"/>
                <DataGridTextColumn Header="Status"        Binding="{Binding Status}"         Width="110"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
          <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,14,0,0">
            <Button x:Name="sh_Add"     Content="Add credential"  Style="{StaticResource Pill}"      Margin="0,0,8,0"/>
            <Button x:Name="sh_Rotate"  Content="Rotate selected" Style="{StaticResource PillGhost}" Margin="0,0,8,0"/>
            <Button x:Name="sh_Remove"  Content="Remove selected" Style="{StaticResource PillGhost}" Margin="0,0,8,0"/>
            <Button x:Name="sh_Test"    Content="Test all"        Style="{StaticResource PillGhost}" Margin="0,0,8,0"/>
            <Button x:Name="sh_Export"  Content="Export metadata" Style="{StaticResource PillGhost}" Margin="0,0,8,0"/>
            <Button x:Name="sh_Refresh" Content="Refresh"         Style="{StaticResource PillGhost}"/>
          </StackPanel>
        </Grid>

        <!-- ─── REPORTS ─── -->
        <Grid x:Name="panel_Reports" Visibility="Collapsed" MaxWidth="1000">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Text="Reports" FontSize="24" FontWeight="Bold"
                     Foreground="{DynamicResource HeadingBrush}" Margin="0,10,0,0"/>
          <TextBlock Grid.Row="1" x:Name="rp_DirHint" Foreground="{DynamicResource MutedBrush}" Margin="0,6,0,16"/>
          <Border Grid.Row="2" BorderBrush="{DynamicResource LineBrush}" BorderThickness="1" CornerRadius="12"
                  Padding="6" ClipToBounds="True">
            <DataGrid x:Name="rp_Grid">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Name"     Binding="{Binding Name}"     Width="*"/>
                <DataGridTextColumn Header="Platform" Binding="{Binding Platform}" Width="150"/>
                <DataGridTextColumn Header="Size KB"  Binding="{Binding SizeKB}"   Width="90"/>
                <DataGridTextColumn Header="Modified" Binding="{Binding Modified}" Width="160"/>
              </DataGrid.Columns>
            </DataGrid>
          </Border>
          <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,14,0,0">
            <Button x:Name="rp_Open"    Content="Open in browser" Style="{StaticResource Pill}"      Margin="0,0,8,0"/>
            <Button x:Name="rp_Pdf"     Content="Convert to PDF"  Style="{StaticResource PillGhost}" Margin="0,0,8,0"/>
            <Button x:Name="rp_Delete"  Content="Delete"          Style="{StaticResource PillGhost}" Margin="0,0,8,0"/>
            <Button x:Name="rp_Refresh" Content="Refresh"         Style="{StaticResource PillGhost}"/>
          </StackPanel>
        </Grid>

        <!-- ─── SETTINGS ─── -->
        <Grid x:Name="panel_Settings" Visibility="Collapsed" MaxWidth="1000">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Text="Settings" FontSize="24" FontWeight="Bold"
                     Foreground="{DynamicResource HeadingBrush}" Margin="0,10,0,0"/>
          <TextBlock Grid.Row="1" Text="Runtime configuration applied to all subsequent scans."
                     Foreground="{DynamicResource MutedBrush}" Margin="0,6,0,16"/>
          <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
            <Border Style="{StaticResource Card}" Padding="24" VerticalAlignment="Top">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="180"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Grid.Column="0" Text="Profile" Foreground="{DynamicResource MutedBrush}"
                           VerticalAlignment="Center" Margin="0,8"/>
                <ComboBox Grid.Row="0" Grid.Column="1" x:Name="st_Profile" Margin="0,8" HorizontalAlignment="Left" Width="220">
                  <ComboBoxItem Content="Default" IsSelected="True"/>
                  <ComboBoxItem Content="K12"/>
                </ComboBox>
                <TextBlock Grid.Row="1" Grid.Column="0" Text="Output directory" Foreground="{DynamicResource MutedBrush}"
                           VerticalAlignment="Center" Margin="0,8"/>
                <Grid Grid.Row="1" Grid.Column="1" Margin="0,8">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <TextBox Grid.Column="0" x:Name="st_OutputDir"/>
                  <Button Grid.Column="1" x:Name="st_BrowseOutput" Content="Browse"
                          Style="{StaticResource PillGhost}" Margin="8,0,0,0"/>
                </Grid>
                <TextBlock Grid.Row="2" Grid.Column="0" Text="Config file path" Foreground="{DynamicResource MutedBrush}"
                           VerticalAlignment="Center" Margin="0,8"/>
                <TextBox Grid.Row="2" Grid.Column="1" x:Name="st_ConfigPath" Margin="0,8" IsReadOnly="True"
                         Foreground="{DynamicResource MutedBrush}"/>
                <TextBlock Grid.Row="3" Grid.Column="1" x:Name="st_StatusLine"
                           Foreground="{DynamicResource OkBrush}" Margin="0,12,0,0"/>
              </Grid>
            </Border>
          </ScrollViewer>
          <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,14,0,0">
            <Button x:Name="st_Apply"  Content="Apply"  Style="{StaticResource Pill}"      Margin="0,0,8,0"/>
            <Button x:Name="st_Revert" Content="Revert" Style="{StaticResource PillGhost}"/>
          </StackPanel>
        </Grid>

        <!-- ─── INSPECTOR ─── -->
        <Grid x:Name="panel_Source" Visibility="Collapsed">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Text="Inspector" FontSize="24" FontWeight="Bold"
                     Foreground="{DynamicResource HeadingBrush}" Margin="0,10,0,0"/>
          <TextBlock Grid.Row="1" Foreground="{DynamicResource MutedBrush}" Margin="0,6,0,16" TextWrapping="Wrap"
                     Text="Read the actual source of every scan, check, and helper in this module. Filter by area or search by name, then select a function to view its code."/>
          <Grid Grid.Row="2" Margin="0,0,0,12">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="240"/>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <ComboBox Grid.Column="0" x:Name="src_AreaFilter" Margin="0,0,8,0"/>
            <TextBox Grid.Column="1" x:Name="src_Search"/>
            <TextBlock Grid.Column="2" x:Name="src_Count" Foreground="{DynamicResource MutedBrush}"
                       VerticalAlignment="Center" Margin="12,0,0,0"/>
          </Grid>
          <Grid Grid.Row="3">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="320"/>
              <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Border Grid.Column="0" BorderBrush="{DynamicResource LineBrush}" BorderThickness="1"
                    CornerRadius="12" Padding="4" ClipToBounds="True">
              <ListBox x:Name="src_List"/>
            </Border>
            <Grid Grid.Column="1" Margin="14,0,0,0">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>
              <Grid Grid.Row="0" Margin="0,0,0,8">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" x:Name="src_Meta" Foreground="{DynamicResource MutedBrush}"
                           VerticalAlignment="Center" TextWrapping="Wrap" Text="Select a function to view its source."/>
                <Button Grid.Column="1" x:Name="src_Copy" Content="Copy" Style="{StaticResource PillGhost}"
                        Margin="8,0,0,0"/>
              </Grid>
              <Border Grid.Row="1" Background="{DynamicResource CodeBgBrush}" CornerRadius="8" Padding="6">
                <TextBox x:Name="src_Code" IsReadOnly="True" FontFamily="Consolas, Courier New" FontSize="12"
                         Background="Transparent" BorderThickness="0" Foreground="{DynamicResource TextBrush}"
                         VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                         VerticalContentAlignment="Stretch"
                         TextWrapping="NoWrap" AcceptsReturn="True" AcceptsTab="True" Padding="8"/>
              </Border>
            </Grid>
          </Grid>
        </Grid>

        <!-- ─── BRANDING ─── -->
        <Grid x:Name="panel_Branding" Visibility="Collapsed" MaxWidth="1000">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Text="Report branding" FontSize="24" FontWeight="Bold"
                     Foreground="{DynamicResource HeadingBrush}" Margin="0,10,0,0"/>
          <TextBlock Grid.Row="1" Foreground="{DynamicResource MutedBrush}" Margin="0,6,0,16" TextWrapping="Wrap"
                     Text="White-label the header of generated reports with your firm's details. The &quot;Generated with Guerrilla by Jim Tyler, Microsoft MVP&quot; attribution always remains in the footer. Saved to your config and applied on the next scan."/>
          <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
            <Border Style="{StaticResource Card}" Padding="24" VerticalAlignment="Top">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="180"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Grid.Column="0" Text="Firm / company name"
                           Foreground="{DynamicResource MutedBrush}" VerticalAlignment="Center" Margin="0,8"/>
                <TextBox Grid.Row="0" Grid.Column="1" x:Name="br_FirmName" Margin="0,8"/>
                <TextBlock Grid.Row="1" Grid.Column="0" Text="Logo (file path or URL)"
                           Foreground="{DynamicResource MutedBrush}" VerticalAlignment="Center" Margin="0,8"/>
                <Grid Grid.Row="1" Grid.Column="1" Margin="0,8">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <TextBox Grid.Column="0" x:Name="br_LogoPath"/>
                  <Button Grid.Column="1" x:Name="br_BrowseLogo" Content="Browse"
                          Style="{StaticResource PillGhost}" Margin="8,0,0,0"/>
                </Grid>
                <TextBlock Grid.Row="2" Grid.Column="0" Text="Consultant name"
                           Foreground="{DynamicResource MutedBrush}" VerticalAlignment="Center" Margin="0,8"/>
                <TextBox Grid.Row="2" Grid.Column="1" x:Name="br_ConsultantName" Margin="0,8"/>
                <TextBlock Grid.Row="3" Grid.Column="0" Text="Consultant email"
                           Foreground="{DynamicResource MutedBrush}" VerticalAlignment="Center" Margin="0,8"/>
                <TextBox Grid.Row="3" Grid.Column="1" x:Name="br_ConsultantEmail" Margin="0,8"/>
                <TextBlock Grid.Row="4" Grid.Column="0" Text="Client / org assessed"
                           Foreground="{DynamicResource MutedBrush}" VerticalAlignment="Center" Margin="0,8"/>
                <TextBox Grid.Row="4" Grid.Column="1" x:Name="br_ClientName" Margin="0,8"/>
                <TextBlock Grid.Row="5" Grid.Column="0" Text="Confidentiality banner"
                           Foreground="{DynamicResource MutedBrush}" VerticalAlignment="Center" Margin="0,8"/>
                <TextBox Grid.Row="5" Grid.Column="1" x:Name="br_Confidentiality" Margin="0,8"/>
                <TextBlock Grid.Row="6" Grid.Column="1" x:Name="br_StatusLine"
                           Foreground="{DynamicResource OkBrush}" Margin="0,12,0,0"/>
              </Grid>
            </Border>
          </ScrollViewer>
          <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,14,0,0">
            <Button x:Name="br_Save"   Content="Save"   Style="{StaticResource Pill}"      Margin="0,0,8,0"/>
            <Button x:Name="br_Revert" Content="Revert" Style="{StaticResource PillGhost}"/>
          </StackPanel>
        </Grid>

      </Grid>
    </DockPanel>
  </Border>
</Window>
'@

    # Parse XAML and find named controls.
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $window = [System.Windows.Markup.XamlReader]::Load($reader)

    # Bind every x:Name'd control into a lookup for the handlers below.
    $namedControls = @{}
    $xpath = "//*[@x:Name]"
    $nsm = New-Object System.Xml.XmlNamespaceManager(([xml]$xaml).NameTable)
    $nsm.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
    foreach ($node in ([xml]$xaml).SelectNodes($xpath, $nsm)) {
        $name = $node.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
        $namedControls[$name] = $window.FindName($name)
    }

    # ── Side-effect-bearing state for the GUI session ─────────────────────
    $session = [PSCustomObject]@{
        Window          = $window
        Controls        = $namedControls
        VaultName       = $VaultName
        ConfigPath      = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
        ModulePath      = $ModulePath
        ReportsDir      = $reportsDir
        CurrentTab      = 'Operations'
        CurrentAsync    = $null
        LastReportPath  = $null
        FunctionIndex   = $null
        Theme           = 'Light'
    }

    $mdot = [string][char]0x00B7   # middle-dot separator used in status strings

    # ── Theme engine ──────────────────────────────────────────────────────
    # Swap every <Token>Brush resource; DynamicResource references restyle live.
    $applyTheme = {
        param([string]$Mode)
        $pal = if ($Mode -eq 'Dark') { $palettes.Dark } else { $palettes.Light }
        foreach ($key in $pal.Keys) {
            $color = [System.Windows.Media.ColorConverter]::ConvertFromString($pal[$key])
            $brush = [System.Windows.Media.SolidColorBrush]::new($color)
            $brush.Freeze()
            $session.Window.Resources["${key}Brush"] = $brush
        }
        $session.Theme = $Mode
        $toggle = $session.Controls['hdr_ThemeToggle']
        if ($Mode -eq 'Dark') {
            $toggle.Content = [string][char]0x2600      # sun: switch back to light
            $toggle.ToolTip = 'Switch to light theme'
        } else {
            $toggle.Content = [string][char]0x263E      # moon: switch to dark
            $toggle.ToolTip = 'Switch to dark theme'
        }
    }

    # Initial theme: explicit config choice wins; otherwise follow the OS app theme.
    $initialTheme = $null
    try {
        if ($session.ConfigPath -and (Test-Path $session.ConfigPath)) {
            $cfg = Get-Content $session.ConfigPath -Raw | ConvertFrom-Json -AsHashtable
            if ($cfg.gui -and $cfg.gui.theme -in @('Light', 'Dark')) { $initialTheme = $cfg.gui.theme }
        }
    } catch { }
    if (-not $initialTheme) {
        try {
            $appsLight = Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' `
                -Name 'AppsUseLightTheme' -ErrorAction Stop
            $initialTheme = if ($appsLight -eq 0) { 'Dark' } else { 'Light' }
        } catch { $initialTheme = 'Light' }
    }
    & $applyTheme $initialTheme

    $session.Controls['hdr_ThemeToggle'].Add_Click({
        $next = if ($session.Theme -eq 'Dark') { 'Light' } else { 'Dark' }
        & $applyTheme $next
        # Persist the choice so the next launch matches (best-effort).
        try {
            $cfg = @{}
            if ($session.ConfigPath -and (Test-Path $session.ConfigPath)) {
                $cfg = Get-Content $session.ConfigPath -Raw | ConvertFrom-Json -AsHashtable
                if (-not $cfg) { $cfg = @{} }
            }
            if (-not $cfg.gui) { $cfg.gui = @{} }
            $cfg.gui.theme = $next
            $dir = Split-Path $session.ConfigPath -Parent
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $cfg | ConvertTo-Json -Depth 8 | Set-Content -Path $session.ConfigPath -Encoding UTF8
        } catch { }
    })

    # ── Window chrome: caption buttons + maximize fix ─────────────────────
    $session.Controls['hdr_Min'].Content   = [string][char]0xE921   # Segoe MDL2: minimize
    $session.Controls['hdr_Max'].Content   = [string][char]0xE922   # Segoe MDL2: maximize
    $session.Controls['hdr_Close'].Content = [string][char]0xE8BB   # Segoe MDL2: close

    $session.Controls['hdr_Min'].Add_Click({ $session.Window.WindowState = 'Minimized' })
    $session.Controls['hdr_Max'].Add_Click({
        $session.Window.WindowState = if ($session.Window.WindowState -eq 'Maximized') { 'Normal' } else { 'Maximized' }
    })
    $session.Controls['hdr_Close'].Add_Click({ $session.Window.Close() })

    # A borderless (WindowStyle=None) window overflows the screen edges by the resize
    # border when maximized; pad the root back into view and swap the caption glyph.
    $window.Add_StateChanged({
        $root = $session.Controls['rootChrome']
        if ($session.Window.WindowState -eq 'Maximized') {
            $root.Margin = [System.Windows.Thickness]::new(7)
            $root.BorderThickness = [System.Windows.Thickness]::new(0)
            $session.Controls['hdr_Max'].Content = [string][char]0xE923   # restore glyph
        } else {
            $root.Margin = [System.Windows.Thickness]::new(0)
            $root.BorderThickness = [System.Windows.Thickness]::new(1)
            $session.Controls['hdr_Max'].Content = [string][char]0xE922
        }
    })

    $session.Controls['foot_Site'].Add_MouseLeftButtonUp({
        try { Start-Process 'https://guerrilla.army' } catch { }
    })

    # ── Micro-animation helpers ───────────────────────────────────────────
    $fadeIn = {
        param($Element)
        $anim = New-Object System.Windows.Media.Animation.DoubleAnimation
        $anim.From = 0.0; $anim.To = 1.0
        $anim.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds(220))
        $ease = New-Object System.Windows.Media.Animation.CubicEase
        $ease.EasingMode = [System.Windows.Media.Animation.EasingMode]::EaseOut
        $anim.EasingFunction = $ease
        $Element.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $anim)
    }

    # Indeterminate "shimmer" bar: a rounded accent segment sweeping the track.
    $startShimmer = {
        $dash = $session.Controls['ops_ProgressDash']
        $tt = New-Object System.Windows.Media.TranslateTransform
        $dash.RenderTransform = $tt
        $anim = New-Object System.Windows.Media.Animation.DoubleAnimation
        $anim.From = -200.0; $anim.To = 1100.0
        $anim.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds(1300))
        $anim.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
        $ease = New-Object System.Windows.Media.Animation.QuadraticEase
        $ease.EasingMode = [System.Windows.Media.Animation.EasingMode]::EaseInOut
        $anim.EasingFunction = $ease
        $tt.BeginAnimation([System.Windows.Media.TranslateTransform]::XProperty, $anim)
        $session.Controls['ops_Progress'].Visibility = 'Visible'
    }
    $stopShimmer = {
        $dash = $session.Controls['ops_ProgressDash']
        if ($dash.RenderTransform -is [System.Windows.Media.TranslateTransform]) {
            $dash.RenderTransform.BeginAnimation([System.Windows.Media.TranslateTransform]::XProperty, $null)
        }
        $session.Controls['ops_Progress'].Visibility = 'Collapsed'
    }

    # ── Navigation ────────────────────────────────────────────────────────
    $setActiveTab = {
        param([string]$Tab)
        foreach ($t in @('Operations', 'Safehouse', 'Reports', 'Settings', 'Source', 'Branding')) {
            $panel  = $session.Controls["panel_$t"]
            $navBtn = $session.Controls["nav_$t"]
            if ($t -eq $Tab) {
                $panel.Visibility = 'Visible'
                $navBtn.Style     = $session.Window.FindResource('NavLinkActive')
                & $fadeIn $panel
            } else {
                $panel.Visibility = 'Collapsed'
                $navBtn.Style     = $session.Window.FindResource('NavLink')
            }
        }
        $session.CurrentTab = $Tab
        # Lazy-load each page's data on visit.
        switch ($Tab) {
            'Safehouse' { & $refreshSafehouseGrid }
            'Reports'   { & $refreshReportsGrid }
            'Settings'  { & $loadSettings }
            'Source'    { & $refreshSourceList }
            'Branding'  { & $loadBranding }
        }
    }

    $appendLog = {
        param([string]$Message)
        $tb = $session.Controls['ops_LogPane']
        # In test mode the log timestamps are zeroed so demo/sample output is deterministic
        # (matches the zeroed in-scan [0000 UTC] stamps from the console helpers).
        $tm = $session.Controls['ops_TestMode']
        $stamp = if ($tm -and $tm.IsChecked) { '00:00:00' } else { [datetime]::Now.ToString('HH:mm:ss') }
        $tb.AppendText("[$stamp] $Message`r`n")
        $tb.ScrollToEnd()
    }

    $resetOperationsUI = {
        & $stopShimmer
        $session.Controls['ops_CancelButton'].Visibility = 'Collapsed'
    }

    # ── Options drawer + category panels ──────────────────────────────────
    $session.Controls['opt_Toggle'].Add_Click({
        $panel = $session.Controls['opt_Panel']
        if ($session.Controls['opt_Toggle'].IsChecked) {
            $panel.Visibility = 'Visible'
            & $fadeIn $panel
        } else {
            $panel.Visibility = 'Collapsed'
        }
    })

    $platformCategories = @{
        AD    = @('DomainForest','Trusts','PrivilegedAccounts','PasswordPolicy','Kerberos','ACLDelegation',
                  'GroupPolicy','LogonScripts','CertificateServices','StaleObjects','Network','TierZero',
                  'Logging','Tradecraft','AttackPath')
        Cloud = @('ConditionalAccess','AuthenticationMethods','PIM','Applications','Federation',
                  'TenantConfig','AzureIAM','Intune','M365Services')
        GWS   = @('Authentication','EmailSecurity','DriveSecurity','OAuthSecurity','AdminManagement',
                  'Collaboration','DeviceManagement','LoggingAlerting','K12')
    }
    $categoryPanelFor = @{ AD = 'opt_CatsAD'; Cloud = 'opt_CatsCloud'; GWS = 'opt_CatsGWS' }

    $buildCategoryPanel = {
        param([string]$PanelName, [string[]]$Categories, [string[]]$DefaultUnchecked)
        $panel = $session.Controls[$PanelName]
        $panel.Children.Clear()

        # "All" toggle first, styled as the group lead.
        $allCb = New-Object System.Windows.Controls.CheckBox
        $allCb.Content    = 'All'
        $allCb.IsChecked  = ($DefaultUnchecked.Count -eq 0)
        $allCb.FontWeight = 'SemiBold'
        $allCb.SetResourceReference([System.Windows.Controls.Control]::ForegroundProperty, 'LinkBrush')
        [void]$panel.Children.Add($allCb)
        $allCb.Add_Checked({
            foreach ($child in $panel.Children) {
                if ($child -is [System.Windows.Controls.CheckBox] -and $child.Content -ne 'All') {
                    $child.IsChecked = $true
                }
            }
        }.GetNewClosure())
        $allCb.Add_Unchecked({
            foreach ($child in $panel.Children) {
                if ($child -is [System.Windows.Controls.CheckBox] -and $child.Content -ne 'All') {
                    $child.IsChecked = $false
                }
            }
        }.GetNewClosure())

        foreach ($cat in $Categories) {
            $cb = New-Object System.Windows.Controls.CheckBox
            $cb.Content   = $cat
            $cb.IsChecked = ($cat -notin $DefaultUnchecked)
            [void]$panel.Children.Add($cb)
        }
    }

    # Email Security starts unchecked for Google Workspace (noisier, slower set).
    & $buildCategoryPanel 'opt_CatsAD'    $platformCategories.AD    @()
    & $buildCategoryPanel 'opt_CatsCloud' $platformCategories.Cloud @()
    & $buildCategoryPanel 'opt_CatsGWS'   $platformCategories.GWS   @('EmailSecurity')

    $getSelectedCategories = {
        param([string]$Platform)
        $cats = @()
        $panelName = $categoryPanelFor[$Platform]
        if (-not $panelName) { return @() }   # Campaign runs the default set
        foreach ($child in $session.Controls[$panelName].Children) {
            if ($child -is [System.Windows.Controls.CheckBox] -and
                $child.Content -ne 'All' -and $child.IsChecked) {
                $cats += [string]$child.Content
            }
        }
        return @($cats)
    }

    $session.Controls['ops_BrowseOutput'].Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.SelectedPath = $session.Controls['ops_OutputDir'].Text
        $dlg.Description  = 'Select output directory for the scan report'
        if ($dlg.ShowDialog() -eq 'OK') {
            $session.Controls['ops_OutputDir'].Text = $dlg.SelectedPath
        }
    })

    # ── The run itself: one button per platform ───────────────────────────
    $platformTitles = @{
        AD       = 'Active Directory'
        Cloud    = 'Entra / Azure / M365'
        GWS      = 'Google Workspace'
        Campaign = 'Campaign: all platforms'
    }
    $platformCmdlets = @{
        AD       = 'Invoke-ADAudit'
        Cloud    = 'Invoke-EntraAudit'
        GWS      = 'Invoke-GWSAudit'
        Campaign = 'Invoke-Campaign'
    }

    $startScan = {
        param([string]$Platform)

        $cmdletName   = $platformCmdlets[$Platform]
        $outDir       = $session.Controls['ops_OutputDir'].Text
        $mode         = if ($session.Controls['ops_ModeFull'].IsChecked) { 'Full' } else { 'Fast' }
        $noReports    = [bool]$session.Controls['ops_NoReports'].IsChecked
        $noDelta      = [bool]$session.Controls['ops_NoDelta'].IsChecked
        $reportStyle  = "$($session.Controls['ops_ReportStyle'].SelectedItem.Content)"
        $testMode     = [bool]$session.Controls['ops_TestMode'].IsChecked
        $selectedCats = & $getSelectedCategories $Platform
        $studentOus   = @("$($session.Controls['ops_StudentOU'].Text)" -split '[,;]' |
            ForEach-Object { $_.Trim() } | Where-Object { $_ })

        # Swap the home cards for the run view.
        $session.Controls['ops_Home'].Visibility = 'Collapsed'
        $session.Controls['ops_Run'].Visibility  = 'Visible'
        & $fadeIn $session.Controls['ops_Run']
        $session.Controls['run_Title'].Text  = $platformTitles[$Platform]
        $session.Controls['run_Status'].Text = "Running $cmdletName (mode: $mode) $mdot the report opens when the run completes"
        $session.Controls['ops_ResultBanner'].Visibility = 'Collapsed'
        $session.Controls['ops_CancelButton'].Visibility = 'Visible'
        $session.Controls['ops_LogPane'].Clear()
        & $startShimmer

        & $appendLog "Starting $cmdletName ($($selectedCats.Count) categories, mode=$mode)..."

        # Pass params explicitly into the scriptblock rather than relying on
        # closure capture — closures don't survive the runspace transfer reliably.
        $action = {
            param([string]$CmdletName, [string]$OutputDir, [string]$Mode,
                  [bool]$NoReports, [bool]$NoDelta, [string[]]$Categories, [string]$VaultName,
                  [string]$ReportStyle, [bool]$TestMode, [string[]]$StudentOU)
            # Only pass parameters the target cmdlet actually declares. The four
            # platform cmdlets have different surfaces (e.g. Invoke-Campaign has no
            # -Categories/-NoReports), so gating on the real parameter set avoids
            # "A parameter cannot be found that matches ..." without maintaining
            # brittle per-cmdlet name lists. The cmdlets auto-resolve credentials
            # from the safehouse vault, so -VaultName is all a vault setup needs.
            $params = (Get-Command $CmdletName).Parameters
            $invokeArgs = @{}
            if ($params.ContainsKey('Quiet'))                                   { $invokeArgs.Quiet = $false }
            if ($VaultName          -and $params.ContainsKey('VaultName'))       { $invokeArgs.VaultName = $VaultName }
            if ($OutputDir          -and $params.ContainsKey('OutputDirectory')) { $invokeArgs.OutputDirectory = $OutputDir }
            if ($NoReports          -and $params.ContainsKey('NoReports'))       { $invokeArgs.NoReports = $true }
            if ($NoDelta            -and $params.ContainsKey('NoDelta'))         { $invokeArgs.NoDelta = $true }
            if ($Categories.Count -gt 0 -and $params.ContainsKey('Categories'))  { $invokeArgs.Categories = $Categories }
            if ($Mode               -and $params.ContainsKey('ScanMode'))        { $invokeArgs.ScanMode = $Mode }
            if ($ReportStyle        -and $params.ContainsKey('ReportStyle'))     { $invokeArgs.ReportStyle = $ReportStyle }
            if ($TestMode           -and $params.ContainsKey('TestMode'))        { $invokeArgs.TestMode = $true }
            if ($StudentOU.Count -gt 0 -and $params.ContainsKey('StudentOU'))    { $invokeArgs.StudentOU = $StudentOU }
            & $CmdletName @invokeArgs
        }
        $actionArgs = @($cmdletName, $outDir, $mode, [bool]$noReports, [bool]$noDelta,
            @($selectedCats), $session.VaultName, $reportStyle, $testMode, @($studentOus))

        # Invoke-GuerrillaGuiAsync fires these callbacks from its own DispatcherTimer
        # scope, so they must carry everything they need by closure. GetNewClosure()
        # snapshots only THIS scriptblock's locals — NOT the function-scope helpers,
        # which are merely *visible* here through the scope chain. Copy them into
        # locals first so the closures actually capture them.
        $appendLog         = $appendLog
        $resetOperationsUI = $resetOperationsUI
        $session           = $session

        $onLog = { param($msg) & $appendLog $msg }.GetNewClosure()

        $onComplete = {
            param($result)
            $reportPath = $null
            if ($result -and $result.HtmlReportPath) {
                $reportPath = $result.HtmlReportPath
            } else {
                # Best-effort: pick the newest HTML in the reports dir
                $newest = Get-ChildItem $session.ReportsDir -Filter '*.html' -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($newest) { $reportPath = $newest.FullName }
            }
            $session.LastReportPath = $reportPath
            & $appendLog 'Scan complete.'
            $session.Controls['run_Status'].Text = 'Complete.'
            $banner = $session.Controls['ops_ResultBanner']
            $banner.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'OkBrush')
            if ($reportPath) {
                $session.Controls['ops_ResultText'].Text = "Report ready: $reportPath"
                $session.Controls['ops_OpenReport'].Visibility = 'Visible'
            } else {
                $session.Controls['ops_ResultText'].Text = 'Scan complete (no report path returned; check the output directory).'
                $session.Controls['ops_OpenReport'].Visibility = 'Collapsed'
            }
            $banner.Visibility = 'Visible'
            & $resetOperationsUI
        }.GetNewClosure()

        $onError = {
            param($err)
            & $appendLog "ERROR: $err"
            $session.Controls['run_Status'].Text = 'Failed.'
            $banner = $session.Controls['ops_ResultBanner']
            $banner.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'BadBrush')
            $session.Controls['ops_ResultText'].Text = "Scan failed: $err"
            $session.Controls['ops_OpenReport'].Visibility = 'Collapsed'
            $banner.Visibility = 'Visible'
            & $resetOperationsUI
        }.GetNewClosure()

        $session.CurrentAsync = Invoke-GuerrillaGuiAsync `
            -ModulePath  $session.ModulePath `
            -Action      $action `
            -Arguments   $actionArgs `
            -Dispatcher  $session.Window.Dispatcher `
            -OnLog       $onLog `
            -OnComplete  $onComplete `
            -OnError     $onError
    }

    foreach ($p in @('AD', 'Cloud', 'GWS', 'Campaign')) {
        $btn = $session.Controls["run_$p"]
        $plat = $p  # capture
        $btn.Add_Click({ & $startScan $plat }.GetNewClosure())
    }

    $session.Controls['ops_CancelButton'].Add_Click({
        if ($session.CurrentAsync) {
            Stop-GuerrillaGuiAsync -State $session.CurrentAsync
            & $appendLog 'Cancelled by user.'
            $session.Controls['run_Status'].Text = 'Cancelled.'
            $banner = $session.Controls['ops_ResultBanner']
            $banner.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, 'WarnBrush')
            $session.Controls['ops_ResultText'].Text = 'Run cancelled before completion.'
            $session.Controls['ops_OpenReport'].Visibility = 'Collapsed'
            $banner.Visibility = 'Visible'
            & $resetOperationsUI
        }
    })

    $session.Controls['ops_OpenReport'].Add_Click({
        if ($session.LastReportPath -and (Test-Path $session.LastReportPath)) {
            Invoke-Item $session.LastReportPath
        }
    })

    $session.Controls['ops_RunAgain'].Add_Click({
        $session.Controls['ops_Run'].Visibility  = 'Collapsed'
        $session.Controls['ops_Home'].Visibility = 'Visible'
        & $fadeIn $session.Controls['ops_Home']
    })

    # ── Safehouse page handlers ───────────────────────────────────────────
    $refreshSafehouseGrid = {
        try {
            $sh = Get-Safehouse -VaultName $session.VaultName -ErrorAction Stop
            $rows = @()
            if ($sh.credentials) {
                foreach ($key in $sh.credentials.Keys) {
                    $c = $sh.credentials[$key]
                    $rows += [PSCustomObject]@{
                        VaultKey        = $key
                        Environment     = $c.environment
                        Description     = $c.description
                        Identity        = $c.identity
                        StoredDate      = if ($c.storedDate) { ([datetime]$c.storedDate).ToString('yyyy-MM-dd') } else { '' }
                        ExpirationDate  = if ($c.expirationDate) { $c.expirationDate } else { '' }
                        Status          = $c.status
                    }
                }
            }
            $session.Controls['sh_Grid'].ItemsSource = $rows
        } catch {
            [System.Windows.MessageBox]::Show("Could not read vault: $_`r`n`r`nThe vault may not be initialized yet. Click 'Add credential' to set it up.", 'Vault unavailable', 'OK', 'Information') | Out-Null
        }
    }

    $session.Controls['sh_Refresh'].Add_Click({ & $refreshSafehouseGrid })

    $session.Controls['sh_Add'].Add_Click({
        try {
            $entries = Show-AddCredentialDialog -Owner $session.Window -Theme $session.Theme
            if (-not $entries) { return }   # cancelled
            # Make sure the vault exists before writing.
            if (-not (Get-SecretVault -Name $session.VaultName -ErrorAction SilentlyContinue)) {
                Initialize-GuerrillaVault -VaultName $session.VaultName | Out-Null
            }
            $n = Save-SafehouseCredentialSet -Entries $entries -VaultName $session.VaultName
            & $refreshSafehouseGrid
            [System.Windows.MessageBox]::Show("Stored $n credential value(s). Use 'Test all' to verify connectivity.", 'Credential saved', 'OK', 'Information') | Out-Null
        } catch {
            [System.Windows.MessageBox]::Show("Could not save credential: $_", 'Error', 'OK', 'Error') | Out-Null
        }
    })

    $session.Controls['sh_Remove'].Add_Click({
        $row = $session.Controls['sh_Grid'].SelectedItem
        if (-not $row) {
            [System.Windows.MessageBox]::Show('Select a credential row first, then click Remove selected.', 'No selection', 'OK', 'Information') | Out-Null
            return
        }
        $ans = [System.Windows.MessageBox]::Show("Remove credential '$($row.VaultKey)'?", 'Confirm', 'YesNo', 'Warning')
        if ($ans -eq 'Yes') {
            try {
                Set-Safehouse -Remove $row.Environment -VaultName $session.VaultName -ErrorAction Stop
                & $refreshSafehouseGrid
            } catch {
                [System.Windows.MessageBox]::Show("Remove failed: $_", 'Error', 'OK', 'Error') | Out-Null
            }
        }
    })

    $session.Controls['sh_Rotate'].Add_Click({
        $row = $session.Controls['sh_Grid'].SelectedItem
        if (-not $row) {
            [System.Windows.MessageBox]::Show('Select a credential row first, then click Rotate selected.', 'No selection', 'OK', 'Information') | Out-Null
            return
        }
        [System.Windows.MessageBox]::Show("To rotate, run from a PowerShell prompt:`r`n`r`n    Set-Safehouse -Rotate $($row.Environment)", 'Rotate credential', 'OK', 'Information') | Out-Null
    })

    $session.Controls['sh_Test'].Add_Click({
        $btn = $session.Controls['sh_Test']
        $btn.IsEnabled = $false
        $btn.Content = 'Testing...'

        $testComplete = {
            param($result)
            $btn.IsEnabled = $true
            $btn.Content = 'Test all'
            $rows = @($result)
            if ($rows.Count -eq 0) {
                [System.Windows.MessageBox]::Show('No credentials were found to test. Add credentials first.', 'Test all', 'OK', 'Information') | Out-Null
                return
            }
            $passStates = @('CONNECTED', 'VALID', 'STORED', 'KERBEROS')
            $pass = @($rows | Where-Object { $passStates -contains $_.Status }).Count
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine("$pass of $($rows.Count) checks passed.")
            $lastEnv = ''
            foreach ($r in $rows) {
                if ($r.Environment -ne $lastEnv) {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine($r.Environment)
                    $lastEnv = $r.Environment
                }
                $icon = if ($passStates -contains $r.Status) { '[OK] ' } else { '[X]  ' }
                $detail = if ($r.Detail) { " - $($r.Detail)" } else { '' }
                [void]$sb.AppendLine("  $icon$($r.Name): $($r.Status) ($($r.ElapsedMs)ms)$detail")
            }
            $icon = if ($pass -eq $rows.Count) { 'Information' } else { 'Warning' }
            [System.Windows.MessageBox]::Show($sb.ToString(), 'Safehouse connectivity test', 'OK', $icon) | Out-Null
        }.GetNewClosure()

        $testError = {
            param($err)
            $btn.IsEnabled = $true
            $btn.Content = 'Test all'
            [System.Windows.MessageBox]::Show("Connectivity test failed: $err", 'Test all', 'OK', 'Error') | Out-Null
        }.GetNewClosure()

        Invoke-GuerrillaGuiAsync `
            -ModulePath $session.ModulePath `
            -Action     { param($VaultName) Test-Safehouse -VaultName $VaultName } `
            -Arguments  @($session.VaultName) `
            -Dispatcher $session.Window.Dispatcher `
            -OnComplete $testComplete `
            -OnError    $testError
    })

    $session.Controls['sh_Export'].Add_Click({
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter   = 'JSON files (*.json)|*.json'
        $dlg.FileName = 'safehouse-metadata.json'
        if ($dlg.ShowDialog()) {
            try {
                Set-Safehouse -ExportMetadata -Path $dlg.FileName -VaultName $session.VaultName -ErrorAction Stop
                [System.Windows.MessageBox]::Show("Exported to $($dlg.FileName)", 'Done', 'OK', 'Information') | Out-Null
            } catch {
                [System.Windows.MessageBox]::Show("Export failed: $_", 'Error', 'OK', 'Error') | Out-Null
            }
        }
    })

    # ── Reports page handlers ─────────────────────────────────────────────
    $session.Controls['rp_DirHint'].Text = "From $($session.ReportsDir). Newest first."

    $refreshReportsGrid = {
        if (-not (Test-Path $session.ReportsDir)) {
            $session.Controls['rp_Grid'].ItemsSource = @()
            return
        }
        $files = Get-ChildItem -Path $session.ReportsDir -Filter '*.html' -File -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending
        $rows = foreach ($f in $files) {
            $platform = switch -Regex ($f.Name) {
                '^[Rr]econnaissance'   { 'Active Directory' }
                '^[Ff]ortification'    { 'Workspace' }
                '^[Ii]nfiltration'     { 'Cloud' }
                '^[Cc]ampaign'         { 'All Platforms' }
                'Executive'            { 'Summary' }
                'Technical'            { 'Technical' }
                'Playbook|Remediation' { 'Remediation' }
                'Dashboard'            { 'Dashboard' }
                default                { 'Other' }
            }
            [PSCustomObject]@{
                Name     = $f.Name
                Platform = $platform
                SizeKB   = [Math]::Round($f.Length / 1KB, 1)
                Modified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                FullPath = $f.FullName
            }
        }
        $session.Controls['rp_Grid'].ItemsSource = @($rows)
    }

    $session.Controls['rp_Refresh'].Add_Click({ & $refreshReportsGrid })

    $session.Controls['rp_Open'].Add_Click({
        $row = $session.Controls['rp_Grid'].SelectedItem
        if ($row -and (Test-Path $row.FullPath)) { Invoke-Item $row.FullPath }
    })

    $session.Controls['rp_Pdf'].Add_Click({
        $row = $session.Controls['rp_Grid'].SelectedItem
        if (-not $row) { return }
        try {
            Export-ReportPdf -InputPath $row.FullPath -ErrorAction Stop
            [System.Windows.MessageBox]::Show('PDF generated next to the HTML report.', 'Done', 'OK', 'Information') | Out-Null
            & $refreshReportsGrid
        } catch {
            [System.Windows.MessageBox]::Show("PDF conversion failed: $_", 'Error', 'OK', 'Error') | Out-Null
        }
    })

    $session.Controls['rp_Delete'].Add_Click({
        $row = $session.Controls['rp_Grid'].SelectedItem
        if (-not $row) { return }
        $ans = [System.Windows.MessageBox]::Show("Delete '$($row.Name)'?", 'Confirm', 'YesNo', 'Warning')
        if ($ans -eq 'Yes') {
            Remove-Item -LiteralPath $row.FullPath -Force -ErrorAction SilentlyContinue
            & $refreshReportsGrid
        }
    })

    # ── Settings page handlers ────────────────────────────────────────────
    $loadSettings = {
        $session.Controls['st_ConfigPath'].Text = $session.ConfigPath
        if ($session.ConfigPath -and (Test-Path $session.ConfigPath)) {
            try {
                $cfg = Get-Content -Path $session.ConfigPath -Raw | ConvertFrom-Json -AsHashtable
                if ($cfg.profile) {
                    foreach ($item in $session.Controls['st_Profile'].Items) {
                        if ("$($item.Content)" -eq $cfg.profile) { $item.IsSelected = $true; break }
                    }
                }
                if ($cfg.output -and $cfg.output.directory) {
                    $session.Controls['st_OutputDir'].Text = $cfg.output.directory
                }
            } catch { }
        }
        $session.Controls['st_StatusLine'].Text = ''
    }

    $session.Controls['st_BrowseOutput'].Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.SelectedPath = $session.Controls['st_OutputDir'].Text
        if ($dlg.ShowDialog() -eq 'OK') {
            $session.Controls['st_OutputDir'].Text = $dlg.SelectedPath
        }
    })

    $session.Controls['st_Apply'].Add_Click({
        try {
            $params = @{
                ConfigPath = $session.ConfigPath
                Profile    = "$($session.Controls['st_Profile'].SelectedItem.Content)"
            }
            if ($session.Controls['st_OutputDir'].Text) {
                $params.OutputDirectory = $session.Controls['st_OutputDir'].Text
            }
            Set-Safehouse @params -ErrorAction Stop | Out-Null
            $session.Controls['st_StatusLine'].SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'OkBrush')
            $session.Controls['st_StatusLine'].Text = "Saved at $([datetime]::Now.ToString('HH:mm:ss'))."
        } catch {
            $session.Controls['st_StatusLine'].SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'BadBrush')
            $session.Controls['st_StatusLine'].Text = "Save failed: $_"
        }
    })

    $session.Controls['st_Revert'].Add_Click({ & $loadSettings })

    # ── Inspector page handlers ───────────────────────────────────────────
    # Map a module-relative file path (and function name as a fallback) to a
    # friendly area label used by the Inspector's area filter.
    $classifyFunctionArea = {
        param([string]$Rel, [string]$Name)
        $p = ($Rel -replace '\\', '/')
        if ($p -match '^Private/AD/'     -or $Name -match '^(Test-AD|Test-TIER|Invoke-AD|Invoke-TierZero)') { return 'Active Directory' }
        if ($p -match '^Private/Audit/'  -or $Name -match '^(Test-(EMAIL|DRIVE|ADMIN|AUTH|COLLAB|GROUP|OAUTH|DEVICE|LOG|GTRADE|GWS)|Invoke-Gws|Invoke-Google)') { return 'Google Workspace' }
        if ($p -match '^Private/Entra/'  -or $Name -match '^(Test-(EID|M365|INTUNE|AZIAM|AIAGENT)|Invoke-Entra|Invoke-M365|Invoke-Azure|Invoke-Intune)') { return 'Entra / Azure / M365' }
        if ($p -match '^Private/Export/') { return 'Reporting & Export' }
        if ($p -match '^Private/Gui/')   { return 'GUI' }
        if ($p -match '^Public/')        { return 'Public cmdlets' }
        return 'Core & helpers'
    }

    # Parse every module .ps1 once and index each function's name, area, source
    # location, and full source text. Built lazily on first Inspector visit.
    $ensureFunctionIndex = {
        if ($session.FunctionIndex) { return }
        $root = Split-Path $session.ModulePath -Parent
        $index = [System.Collections.Generic.List[object]]::new()
        foreach ($sub in @('Public', 'Private')) {
            $dir = Join-Path $root $sub
            if (-not (Test-Path $dir)) { continue }
            foreach ($file in (Get-ChildItem -Path $dir -Recurse -Filter *.ps1 -File)) {
                $tokens = $null; $perrors = $null
                try {
                    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$perrors)
                } catch { continue }
                $funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
                foreach ($fn in $funcs) {
                    $rel = $file.FullName.Substring($root.Length).TrimStart('\', '/')
                    $index.Add([PSCustomObject]@{
                        Name      = $fn.Name
                        Area      = (& $classifyFunctionArea $rel $fn.Name)
                        RelFile   = $rel
                        StartLine = $fn.Extent.StartLineNumber
                        Source    = $fn.Extent.Text
                    })
                }
            }
        }
        $session.FunctionIndex = @($index | Sort-Object Area, Name)

        # Populate the area filter dropdown once: "All areas" + each distinct area.
        $combo = $session.Controls['src_AreaFilter']
        if ($combo.Items.Count -eq 0) {
            $allItem = New-Object System.Windows.Controls.ComboBoxItem
            $allItem.Content = 'All areas'
            [void]$combo.Items.Add($allItem)
            foreach ($area in (@($session.FunctionIndex.Area) | Sort-Object -Unique)) {
                $ci = New-Object System.Windows.Controls.ComboBoxItem
                $ci.Content = $area
                [void]$combo.Items.Add($ci)
            }
            $combo.SelectedIndex = 0
        }
    }

    # Filter the index by area + search term and rebuild the function list.
    $refreshSourceList = {
        & $ensureFunctionIndex
        $area = if ($session.Controls['src_AreaFilter'].SelectedItem) {
            [string]$session.Controls['src_AreaFilter'].SelectedItem.Content
        } else { 'All areas' }
        $term = [string]$session.Controls['src_Search'].Text
        $items = @($session.FunctionIndex)
        if ($area -and $area -ne 'All areas') { $items = @($items | Where-Object { $_.Area -eq $area }) }
        if ($term) { $items = @($items | Where-Object { $_.Name -like "*$term*" }) }

        $list = $session.Controls['src_List']
        $list.Items.Clear()
        foreach ($it in $items) {
            $li = New-Object System.Windows.Controls.ListBoxItem
            $li.Content = $it.Name
            $li.Tag     = $it
            [void]$list.Items.Add($li)
        }
        $session.Controls['src_Count'].Text = "$($items.Count) function(s)"
    }

    $session.Controls['src_List'].Add_SelectionChanged({
        $sel = $session.Controls['src_List'].SelectedItem
        if (-not $sel) { return }
        $info = $sel.Tag
        $session.Controls['src_Code'].Text = $info.Source
        $session.Controls['src_Meta'].Text = "$($info.Name)   $mdot   $($info.RelFile) : line $($info.StartLine)   $mdot   $($info.Area)"
    })
    $session.Controls['src_Search'].Add_TextChanged({ & $refreshSourceList })
    $session.Controls['src_AreaFilter'].Add_SelectionChanged({ & $refreshSourceList })
    $session.Controls['src_Copy'].Add_Click({
        $code = $session.Controls['src_Code'].Text
        if ($code) { try { [System.Windows.Clipboard]::SetText($code) } catch { } }
    })

    # ── Branding (white-label) page handlers ──────────────────────────────
    $loadBranding = {
        $b = @{}
        try {
            if ($session.ConfigPath -and (Test-Path $session.ConfigPath)) {
                $cfg = Get-Content $session.ConfigPath -Raw | ConvertFrom-Json -AsHashtable
                if ($cfg.branding) { $b = $cfg.branding }
            }
        } catch { }
        $session.Controls['br_FirmName'].Text        = [string]($b.FirmName ?? '')
        $session.Controls['br_LogoPath'].Text        = [string]($b.LogoPath ?? '')
        $session.Controls['br_ConsultantName'].Text  = [string]($b.ConsultantName ?? '')
        $session.Controls['br_ConsultantEmail'].Text = [string]($b.ConsultantEmail ?? '')
        $session.Controls['br_ClientName'].Text      = [string]($b.ClientName ?? '')
        $session.Controls['br_Confidentiality'].Text = [string]($b.Confidentiality ?? '')
        $session.Controls['br_StatusLine'].SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'OkBrush')
        $session.Controls['br_StatusLine'].Text = ''
    }

    $session.Controls['br_BrowseLogo'].Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'Images|*.png;*.jpg;*.jpeg;*.gif;*.svg|All files|*.*'
        if ($dlg.ShowDialog() -eq 'OK') { $session.Controls['br_LogoPath'].Text = $dlg.FileName }
    })

    $session.Controls['br_Save'].Add_Click({
        try {
            $cfg = @{}
            if ($session.ConfigPath -and (Test-Path $session.ConfigPath)) {
                $cfg = Get-Content $session.ConfigPath -Raw | ConvertFrom-Json -AsHashtable
            }
            if (-not $cfg) { $cfg = @{} }
            $cfg.branding = @{
                FirmName        = $session.Controls['br_FirmName'].Text
                LogoPath        = $session.Controls['br_LogoPath'].Text
                ConsultantName  = $session.Controls['br_ConsultantName'].Text
                ConsultantEmail = $session.Controls['br_ConsultantEmail'].Text
                ClientName      = $session.Controls['br_ClientName'].Text
                Confidentiality = $session.Controls['br_Confidentiality'].Text
            }
            $dir = Split-Path $session.ConfigPath -Parent
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $cfg | ConvertTo-Json -Depth 8 | Set-Content -Path $session.ConfigPath -Encoding UTF8
            $session.Controls['br_StatusLine'].SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'OkBrush')
            $session.Controls['br_StatusLine'].Text = "Saved at $([datetime]::Now.ToString('HH:mm:ss')). Applied on your next scan."
        } catch {
            $session.Controls['br_StatusLine'].SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'BadBrush')
            $session.Controls['br_StatusLine'].Text = "Save failed: $_"
        }
    })
    $session.Controls['br_Revert'].Add_Click({ & $loadBranding })

    # ── Nav button wiring ─────────────────────────────────────────────────
    foreach ($t in @('Operations', 'Safehouse', 'Reports', 'Settings', 'Source', 'Branding')) {
        $btn = $session.Controls["nav_$t"]
        $tab = $t  # capture
        $btn.Add_Click({ & $setActiveTab $tab }.GetNewClosure())
    }

    # ── Initial state ─────────────────────────────────────────────────────
    $session.Controls['ops_OutputDir'].Text = $session.ReportsDir
    # Read the version from the manifest so the footer can't drift like it did at v2.3.0.
    $guiVersion = try { (Import-PowerShellDataFile $session.ModulePath).ModuleVersion } catch { $null }
    $verText = if ($guiVersion) { "Guerrilla v$guiVersion" } else { 'Guerrilla' }
    $session.Controls['foot_Info'].Text = "$verText  $mdot  Vault: $($session.VaultName)  $mdot  Read-only"
    & $setActiveTab $StartOn

    # Single-instance guard. Two windows share config.json + platform *-state.json files,
    # so a second instance would clobber state (last-writer-wins). Refuse the second window —
    # but self-heal: the old guard used initiallyOwned + createdNew, which reported "already
    # open" whenever the *named* mutex still existed (a launch that threw or was force-killed,
    # or a still-alive prior session, left the handle open and never cleared). Now:
    #   - dispose any stale handle from an earlier launch in THIS session,
    #   - WaitOne(0) to test real ownership, treating an AbandonedMutex (previous owner exited
    #     without releasing) as "we own it now" rather than a permanent block.
    if ($script:GuerrillaGuiMutex) {
        try { $script:GuerrillaGuiMutex.Dispose() } catch {}
        $script:GuerrillaGuiMutex = $null
    }
    $haveLock = $false
    try {
        $m = New-Object System.Threading.Mutex($false, 'Global\Guerrilla.GuiSingleInstance')
        try { $haveLock = $m.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $haveLock = $true }  # prior owner died without releasing
        if ($haveLock) { $script:GuerrillaGuiMutex = $m } else { $m.Dispose() }
    } catch {
        # Mutex unavailable (rare) — fail open rather than block the GUI entirely.
        $haveLock = $true
        $script:GuerrillaGuiMutex = $null
    }
    if (-not $haveLock) {
        # Advisory, not absolute: the "holder" may be a stranded/zombie process (a prior launch
        # whose window got lost behind a hidden console) that still holds the OS mutex. Refusing
        # outright traps the user. Let them open anyway; only the genuine two-live-windows case
        # risks state clobbering, and they're told.
        $resp = [System.Windows.MessageBox]::Show(
            "Guerrilla appears to already be open in another window. Two windows share the same config/state files (last save wins).`n`nOpen a new window anyway?`n  Yes = open it now    No = switch to the existing window (Alt+Tab)",
            'Already running', 'YesNo', 'Warning')
        if ($resp -ne 'Yes') { return }
        # Proceeding without the lock — the other process owns it, so we must not release it on close.
        $script:GuerrillaGuiMutex = $null
    }

    # Cleanup on window close (stop any running scan). The single-instance lock is released in
    # the finally below so it is freed even if Closing never fires (window threw before opening).
    $window.Add_Closing({
        if ($session.CurrentAsync) {
            Stop-GuerrillaGuiAsync -State $session.CurrentAsync
        }
    })

    # Bring the window to the front on first render so it can't open hidden behind other windows
    # (which, with the console hidden, is how a launch gets stranded). A brief Topmost flash +
    # Activate pulls it forward without keeping it always-on-top.
    $window.Add_ContentRendered({
        try { $window.Activate(); $window.Topmost = $true; $window.Topmost = $false } catch {}
    })

    # Block until the user closes the window, then always release the single-instance lock.
    try {
        [void]$window.ShowDialog()
    } finally {
        if ($script:GuerrillaGuiMutex) {
            try { $script:GuerrillaGuiMutex.ReleaseMutex() } catch {}
            try { $script:GuerrillaGuiMutex.Dispose() } catch {}
            $script:GuerrillaGuiMutex = $null
        }
    }
}
