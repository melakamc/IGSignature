//
//  IGSignatureRequest.m
//  IGSignature
//
//  Created by Chong Francis on 13年4月1日.
//  Copyright (c) 2013年 Ignition Soft. All rights reserved.
//

#import "IGSignatureRequest.h"
#import "IGSignatureToken.h"
#import "IGQueryEncoder.h"
#import "NSString+SHA256HMAC.h"
#import "OrderedDictionary.h"

@implementation IGSignatureRequest
    
-(id) initWithMethod:(NSString*)method path:(NSString*)path query:(NSDictionary*)theQuery {
    self = [super init];
    if (self) {
        self.path = path;
        NSMutableDictionary* auth = [NSMutableDictionary dictionary];
        NSMutableDictionary* query = [NSMutableDictionary dictionary];
        
        [theQuery enumerateKeysAndObjectsUsingBlock:^(NSString* key, NSString* obj, BOOL *stop) {
            NSString* lowerKey = [key lowercaseString];
            if ([lowerKey hasPrefix:@"auth_"]) {
                [auth setObject:obj forKey:lowerKey];
            } else {
                [query setObject:obj forKey:lowerKey];
            }
        }];
        self.auth = [auth copy];
        self.query = [self sortParameters:query];
        self.method = [method uppercaseString];
        
        _signed = NO;
    }
    return self;
}
    
- (NSDictionary *)sortParameters:(NSMutableDictionary *)params{
    [params enumerateKeysAndObjectsUsingBlock:^(NSString *  _Nonnull paramKey, id  _Nonnull obj, BOOL * _Nonnull stop) {
        if ([obj isKindOfClass:[NSDictionary class]]) {
            MutableOrderedDictionary *tempObj = [MutableOrderedDictionary new];
            
            NSArray * sortedKeys = [[obj allKeys] sortedArrayUsingSelector: @selector(localizedCaseInsensitiveCompare:)];
            
            
            for (NSString *key in sortedKeys) {
                
                [tempObj setValue:[(NSDictionary *)obj objectForKey:key] forKey:key];
            }
            
            [params setObject:tempObj forKey:paramKey];
            
        }else if([obj isKindOfClass:[NSArray class]]){
            
            NSMutableArray *tmpObj = [NSMutableArray new];
            for (int i = 0; i < [(NSArray *)obj count]; i++) {
                
                id childObj = [(NSArray *)obj objectAtIndex:i];
                if ([childObj isKindOfClass:[NSDictionary class]]) {
                    
                    MutableOrderedDictionary *tempDict = [MutableOrderedDictionary new];
                    NSArray * sortedKeys = [[childObj allKeys] sortedArrayUsingSelector: @selector(localizedCaseInsensitiveCompare:)];
                    
                    for (NSString *key in sortedKeys) {
                        
                        id innerObj = [(NSDictionary *)childObj objectForKey:key];
                        if ([innerObj isKindOfClass:[NSDictionary class]]) {
                            MutableOrderedDictionary *innerTempDict = [MutableOrderedDictionary new];
                            NSArray * innerSortedKeys = [[innerObj allKeys] sortedArrayUsingSelector: @selector(localizedCaseInsensitiveCompare:)];
                            for (NSString *innerKey in innerSortedKeys) {
                                [innerTempDict setValue:[(NSDictionary *)innerObj objectForKey:innerKey] forKey:innerKey];
                            }
                            [tempDict setObject:innerTempDict forKey:key];
                        }else{
                            [tempDict setValue:innerObj forKey:key];
                        }
                    }
                    [tmpObj addObject:tempDict];
                }else{
                    [tmpObj addObject:childObj];
                }
            }
            
            [params setObject:tmpObj forKey:paramKey];
        }
    }];
    
    return params;
}
    
    
-(NSDictionary*) sign:(IGSignatureToken*)token {
    return [self sign:token withTime:[NSDate date]];
}
    
-(NSDictionary*) sign:(IGSignatureToken*)token withTime:(NSDate*)time {
    NSAssert(token.key != nil, @"token key cannot be nil");
    NSAssert(time != nil, @"time cannot be nil");
    
    NSString* timestamp = [NSString stringWithFormat:@"%lld",
                           [[NSNumber numberWithDouble:[time timeIntervalSince1970]] longLongValue]];
    self.auth = @{
                  @"auth_version": @"1.0",
                  @"auth_key": token.key,
                  @"auth_timestamp": timestamp
                  };
    NSString* signature = [self signatureWithToken:token];
    self.auth = @{
                  @"auth_version": @"1.0",
                  @"auth_key": token.key,
                  @"auth_timestamp": timestamp,
                  @"auth_signature": signature
                  };
    
    _signed = YES;
    return self.auth;
}
    
-(NSString*) signatureWithToken:(IGSignatureToken*)token {
    return [[self stringToSign] SHA256HMACWithKey:token.secret];
}
    
-(NSString*) stringToSign {
    NSArray* components = @[self.method, self.path, self.parameterString];
    return [components componentsJoinedByString:@"\n"];
}
    
#pragma mark - Private
    
-(NSString*) parameterString {
    NSMutableDictionary* params = [NSMutableDictionary dictionaryWithDictionary:self.query];
    if (self.auth) {
        [params addEntriesFromDictionary:self.auth];
    }
    
    // Convert keys to lowercase strings
    NSMutableDictionary* lowerCaseParams = [NSMutableDictionary dictionaryWithCapacity:[params count]];
    [params enumerateKeysAndObjectsUsingBlock:^(NSString* rootkey, id obj, BOOL *stop) {
        if ([obj isKindOfClass:[NSDictionary class]]) {
            
            //additional step to make sure all child parameters are sorted
            NSArray * sortedKeys = [[obj allKeys] sortedArrayUsingSelector: @selector(localizedCaseInsensitiveCompare:)];
            
            
            for (NSString *key in sortedKeys) {
                
                id innerObj = [(NSDictionary *)obj objectForKey:key] ;
                if ([innerObj isKindOfClass:[NSDictionary class]]) {
                    //additional step to make sure all child parameters are sorted
                    NSArray * childSortedKeys = [[innerObj allKeys] sortedArrayUsingSelector: @selector(localizedCaseInsensitiveCompare:)];
                    
                    
                    for (NSString *childKey in childSortedKeys) {
                        
                        [lowerCaseParams setObject:[(NSDictionary *)innerObj objectForKey:childKey] forKey:[NSString stringWithFormat:@"%@[%@][%@]",[rootkey lowercaseString],key,childKey]];
                        
                    }
                    
                }else{
                    [lowerCaseParams setObject:innerObj forKey:[NSString stringWithFormat:@"%@[%@]",[rootkey lowercaseString],key]];
                }
            }
            
        }else if([obj isKindOfClass:[NSArray class]]){
            for (int i=0; i < [(NSArray *)obj count] ; i++) {
                id childObj = [(NSArray *)obj objectAtIndex:i];
                
                if ([childObj isKindOfClass:[NSDictionary class]]) {
                    
                    
                    
                    NSArray * sortedKeys = [[childObj allKeys] sortedArrayUsingSelector: @selector(localizedCaseInsensitiveCompare:)];
                    
                    
                    for (NSString *key in sortedKeys) {
                        
                        id innerObj = [(NSDictionary *)childObj objectForKey:key] ;
                        
                        if ([innerObj isKindOfClass:[NSDictionary class]]) {
                            //additional step to make sure all child parameters are sorted
                            NSArray * childSortedKeys = [[innerObj allKeys] sortedArrayUsingSelector: @selector(localizedCaseInsensitiveCompare:)];
                            
                            
                            for (NSString *childKey in childSortedKeys) {
                                
                                [lowerCaseParams setObject:[(NSDictionary *)innerObj objectForKey:childKey] forKey:[NSString stringWithFormat:@"%@[%zd][%@][%@]",[rootkey lowercaseString],i,key, childKey]];
                                
                            }
                            
                        }else{
                            [lowerCaseParams setObject:innerObj forKey:[NSString stringWithFormat:@"%@[%zd][%@]",[rootkey lowercaseString],i,key]];
                        }
                        
                        
                    }
                    
                }else{
                    [lowerCaseParams setObject:childObj forKey:[NSString stringWithFormat:@"%@[%zd]",[rootkey lowercaseString],i]];
                }
            }
            
        }else{
            
            [lowerCaseParams setObject:obj forKey:[rootkey lowercaseString]];
        }
    }];
    
    
    // Exclude signature from signature generation!
    [lowerCaseParams removeObjectForKey:@"auth_signature"];
    
    NSArray* sortedKeys = [[lowerCaseParams allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray* encodedParamerers = [NSMutableArray array];
    [sortedKeys enumerateObjectsUsingBlock:^(NSString* key, NSUInteger idx, BOOL *stop) {
        [encodedParamerers addObject:[IGQueryEncoder encodeParamWithoutEscapingUsingKey:key
                                                                               andValue:[lowerCaseParams objectForKey:key]]];
    }];
    
    //NSLog(@"%@",[encodedParamerers componentsJoinedByString:@"&"]);
    return [encodedParamerers componentsJoinedByString:@"&"];
}
    
    
    @end
