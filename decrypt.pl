#!/usr/bin/perl -w

use Mail::GPG;
use MIME::Parser;

use strict;

my $passphrase = '';
my @lines;
my $tmpdir = '/tmp';

########
# Main #
########

my $stdin = &stdin();
my $unencrypted_body = &parse_email($stdin);

if ($unencrypted_body) {

    foreach ($$unencrypted_body) {
        chomp $_;
        push( @lines, $_ );
        print "$_\n"; ## Debugging
    }
}


###############
# Subroutines #
###############

sub stdin {
    #Process stdin
    my $stdin = '';

   while(<ARGV>){
   $stdin .= $_;
   }
    
   if ($stdin eq '') {
        die ("Error: stdin appears to have no content.");
   }

    return $stdin;
}

sub parse_email {

    my $stdin = shift @_;
    my $decoded_body_sref;
    my $entity;

    #Create new MIME Parser obj
    my $parser = MIME::Parser->new;
    
    #Configure MIME Parser
    $parser->decode_bodies(0);
    $parser->output_under($tmpdir);
    
    #Parse the email from stdin
    eval { $entity = $parser->parse_data($stdin) };
    
    # See Mail::GPG for reasoning
    # http://search.cpan.org/~jred/Mail-GPG-1.0.7/lib/Mail/GPG.pm#METHODS_FOR_PARSING,_DECRYPTION_AND_VERIFICATION
    if ( $entity->effective_type ne 'multipart/signed' and
         $entity->effective_type ne 'multipart/encrypted' ) {
    
            #delete tmp files
            $parser->filer->purge;
    
            #enable docode_bodies
            $parser->decode_bodies(1);

            #Parse the email from stdin
            eval { $entity = $parser->parse_data($stdin) };

            #decrypt
            eval { $decoded_body_sref = &decode($entity) };
            if ($@) {
                warn ("Error: $@");
            }
            
            #delete tmp files
            $parser->filer->purge;
    } 
    else {
    
        #decrypt
        eval { $decoded_body_sref = &decode($entity) };
        if ($@) {
            warn ("Error $@");
        }

        #delete tmp files
        $parser->filer->purge;

    }

    return $decoded_body_sref;
}

sub decode {

    my $entity = shift @_;

    #Create new Mail GPG obj
    my $mg = Mail::GPG->new;

    #Decrypt the email from stdin
    my ($decrypted_entity, $result) = $mg->decrypt (
        entity     => $entity,
        passphrase => $passphrase
    );

    #Get a reference to the decoded message body
    my $decoded_body_sref = $result->get_gpg_stdout;

    return $decoded_body_sref;
}

exit;
